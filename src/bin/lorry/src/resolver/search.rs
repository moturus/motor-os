use super::*;

enum Choice {
    Selected(PackageKey),
    New(PackageKey, Arc<Candidate>),
}

/// Dependencies waiting for resolution, in Cargo's order. Each activation
/// adds a group of its dependencies. The next dependency comes from the group
/// whose next dependency has the fewest candidates; ties go to the older group.
#[derive(Clone, Default)]
pub(super) struct Pending {
    // Groups whose candidates are not counted yet, with their insertion time.
    new: Vec<(u64, Vec<Event>)>,
    groups: BTreeMap<(usize, u64), VecDeque<(usize, Event)>>,
    time: u64,
}

impl Pending {
    pub(super) fn push_group(&mut self, events: Vec<Event>) {
        if !events.is_empty() {
            self.new.push((self.time, events));
            self.time += 1;
        }
    }

    /// Loads and counts the candidates of new groups, as Cargo does when it
    /// activates a package, then sorts each group by count.
    fn count(
        &mut self,
        catalog: &mut Catalog,
        locked: &[LockedPreference],
        scope: Scope<'_>,
        loader: &mut dyn FnMut(&str, &VersionReq, &mut Catalog) -> Result<()>,
    ) -> std::result::Result<(), Failure> {
        for (time, events) in std::mem::take(&mut self.new) {
            let mut group = Vec::with_capacity(events.len());
            for mut event in events {
                if event.dependency.source == RequirementSource::CratesIo {
                    loader(
                        &event.dependency.package,
                        &event.dependency.requirement,
                        catalog,
                    )
                    .map_err(|error| Failure::from_error(error, true))?;
                }
                catalog
                    .prepare(&mut event.dependency)
                    .map_err(|error| Failure::from_error(error, false))?;
                let filter = Filter::new(scope, locked, &event)?;
                let keys = candidates(catalog, &event, locked)
                    .iter()
                    .map(|record| candidate_key(record))
                    .filter(|key| filter.permits(key))
                    .collect::<Vec<_>>();
                // A locked edge narrows Cargo's query to the locked version.
                let preferred = keys.iter().filter(|key| filter.is_preferred(key)).count();
                let count = if preferred > 0 { preferred } else { keys.len() };
                group.push((count, event));
            }
            group.sort_by_key(|(count, _)| *count);
            self.groups.insert((group[0].0, time), group.into());
        }
        Ok(())
    }

    fn pop(&mut self) -> Option<Event> {
        let ((_, time), mut group) = self.groups.pop_first()?;
        let (_, event) = group.pop_front().unwrap();
        if let Some((count, _)) = group.front() {
            self.groups.insert((*count, time), group);
        }
        Some(event)
    }
}

/// The locked and preferred identities that limit one dependency's candidates.
struct Filter {
    locked_package: Option<PackageKey>,
    allowed: Option<BTreeSet<locked::Identity>>,
    preferred: Option<BTreeSet<locked::Identity>>,
}

impl Filter {
    fn new(
        scope: Scope<'_>,
        locked: &[LockedPreference],
        event: &Event,
    ) -> std::result::Result<Self, Failure> {
        let mut preferred = scope.dependency_preferences(event).cloned();
        let forced = locked
            .iter()
            .filter(|preference| {
                preference.name == event.dependency.package && preference.checksum.is_none()
            })
            .map(|preference| {
                locked::Identity::from_key(&PackageKey {
                    name: preference.name.clone(),
                    version: preference.version.clone(),
                    source: PackageSourceKey::CratesIo,
                })
            })
            .collect::<BTreeSet<_>>();
        if !forced.is_empty() && event.dependency.source == RequirementSource::CratesIo {
            preferred = Some(forced);
        }
        Ok(Self {
            locked_package: scope.locked_package(event)?.cloned(),
            allowed: scope.locked_dependencies(event)?.cloned(),
            preferred,
        })
    }

    fn permits(&self, key: &PackageKey) -> bool {
        self.locked_package
            .as_ref()
            .is_none_or(|locked| locked == key)
            && self
                .allowed
                .as_ref()
                .is_none_or(|allowed| allowed.contains(&locked::Identity::from_key(key)))
    }

    fn is_preferred(&self, key: &PackageKey) -> bool {
        self.preferred
            .as_ref()
            .is_none_or(|preferred| preferred.contains(&locked::Identity::from_key(key)))
    }
}

fn candidate_key(record: &Candidate) -> PackageKey {
    PackageKey {
        name: record.name.clone(),
        version: record.version.clone(),
        source: record.source.key(),
    }
}

struct Frame {
    state: State,
    pending: Pending,
    event: Option<Event>,
    filter: Option<Filter>,
    // Untried candidates in Cargo's order, including selected packages.
    choices: VecDeque<Choice>,
    tried: BTreeSet<PackageKey>,
    // Catalog records for the dependency name when `choices` was ordered.
    ordered_records: Option<usize>,
    last_failure: Option<Failure>,
}

impl Frame {
    fn new(state: State, pending: Pending) -> Self {
        Self {
            state,
            pending,
            event: None,
            filter: None,
            choices: VecDeque::new(),
            tried: BTreeSet::new(),
            ordered_records: None,
            last_failure: None,
        }
    }

    fn next(
        &mut self,
        catalog: &mut Catalog,
        options: &Options,
        locked: &[LockedPreference],
        scope: Scope<'_>,
        loader: &mut dyn FnMut(&str, &VersionReq, &mut Catalog) -> Result<()>,
    ) -> std::result::Result<Option<(State, Pending)>, Failure> {
        if self.event.is_none() {
            self.pending.count(catalog, locked, scope, loader)?;
            let Some(event) = self.pending.pop() else {
                return Ok(None);
            };
            if let Some(limit) = options.max_depth
                && event.depth > limit
            {
                return Err(Failure::new(format!(
                    "`{}` exceeds dependency depth {}",
                    event.dependency.package, limit
                )));
            }
            self.filter = Some(Filter::new(scope, locked, &event)?);
            self.event = Some(event);
        }
        loop {
            let known = catalog
                .records(&self.event.as_ref().unwrap().dependency.package)
                .len();
            if self.ordered_records != Some(known) {
                // A failed choice may have loaded more versions through its
                // children; order them with the untried candidates.
                self.order_choices(catalog, options, locked);
                self.ordered_records = Some(known);
            }
            let Some(choice) = self.choices.pop_front() else {
                break;
            };
            let (Choice::Selected(key) | Choice::New(key, _)) = &choice;
            self.tried.insert(key.clone());
            let event = self.event.as_ref().unwrap();
            let mut state;
            let key = match choice {
                Choice::Selected(key) => {
                    state = self.state.clone();
                    key
                }
                Choice::New(key, record) => {
                    if self.conflicts(&record) {
                        if self.last_failure.is_none() {
                            self.last_failure = Some(Failure::new(format!(
                                "compatible requirements for `{}` cannot be unified",
                                record.name
                            )));
                        }
                        continue;
                    }
                    let limit = &options.package_limit;
                    if limit.counts(&key)
                        && self
                            .state
                            .nodes
                            .keys()
                            .filter(|key| limit.counts(key))
                            .count() as u64
                            >= limit.max
                    {
                        return Err(Failure::package_limit());
                    }
                    state = self.state.clone();
                    if let Some(links) = &record.links {
                        if let Some(existing) = state.links.get(links) {
                            self.last_failure = Some(Failure::new(format!(
                                "packages `{}` and `{}` both link native library `{links}`",
                                existing.name, key.name
                            )));
                            continue;
                        }
                        state.links.insert(links.clone(), key.clone());
                    }
                    state.nodes.insert(
                        key.clone(),
                        Arc::new(Node {
                            record,
                            activations: BTreeMap::new(),
                            compile_kinds: BTreeSet::new(),
                            edges: BTreeMap::new(),
                        }),
                    );
                    key
                }
            };
            let mut pending = self.pending.clone();
            match fulfill(&mut state, &mut pending, event, &key, options, scope) {
                Ok(()) => return Ok(Some((state, pending))),
                Err(failure) if failure.fatal => return Err(failure),
                Err(failure) => self.last_failure = Some(failure),
            }
        }
        let event = self.event.as_ref().unwrap();
        Err(self.last_failure.take().unwrap_or_else(|| {
            Failure::new(format!(
                "no version of `{}` matches `{}`",
                event.dependency.package, event.dependency.requirement
            ))
        }))
    }

    /// Orders candidates as Cargo does: edge preferences, then lock
    /// preferences, Rust-version compatibility, and the highest version. A
    /// selected package keeps its place in that order, so a higher
    /// semver-incompatible version wins over reusing a lower one.
    fn order_choices(&mut self, catalog: &Catalog, options: &Options, locked: &[LockedPreference]) {
        let event = self.event.as_ref().unwrap();
        let filter = self.filter.as_ref().unwrap();
        let mut records = self
            .state
            .nodes
            .iter()
            .filter(|(key, node)| {
                key.name == event.dependency.package
                    && event.dependency.matches_version(&key.version)
                    && source_matches(&node.record.source, &event.dependency.source)
            })
            .map(|(key, node)| (key.clone(), node.record.clone()))
            .collect::<BTreeMap<_, _>>();
        for record in candidates(catalog, event, locked) {
            records.entry(candidate_key(&record)).or_insert(record);
        }
        let mut ordered = records
            .into_iter()
            .filter(|(key, _)| !self.tried.contains(key) && filter.permits(key))
            .collect::<Vec<_>>();
        ordered.sort_by(|(left_key, left), (right_key, right)| {
            filter
                .is_preferred(right_key)
                .cmp(&filter.is_preferred(left_key))
                .then_with(|| candidate_order(left, right, options, locked))
        });
        self.choices = ordered
            .into_iter()
            .map(|(key, record)| {
                if self.state.nodes.contains_key(&key) {
                    Choice::Selected(key)
                } else {
                    Choice::New(key, record)
                }
            })
            .collect();
    }

    /// In an exact locked resolution, fresh candidates are limited to the
    /// parent's locked identities. When each identity with this name is
    /// already selected, loading candidates cannot add a choice, so the frame
    /// need not be kept for backtracking.
    fn locked_candidates_selected(&self) -> bool {
        let name = &self.event.as_ref().unwrap().dependency.package;
        let filter = self.filter.as_ref().unwrap();
        filter.allowed.as_ref().is_some_and(|allowed| {
            allowed
                .iter()
                .filter(|identity| identity.name() == name)
                .all(|identity| {
                    self.state.nodes.keys().any(|key| {
                        key.name == *name && locked::Identity::from_key(key) == *identity
                    })
                })
        })
    }

    fn conflicts(&self, record: &Candidate) -> bool {
        let event = self.event.as_ref().unwrap();
        self.state.nodes.iter().any(|(key, node)| {
            key.name == record.name
                && source_matches(&node.record.source, &event.dependency.source)
                && semver_compatible(&key.version, &record.version)
        })
    }

    fn can_retry(&self) -> bool {
        // The loader may still add versions of a crates.io package.
        if self.filter.as_ref().unwrap().locked_package.is_none()
            && self.event.as_ref().unwrap().dependency.source == RequirementSource::CratesIo
            && !self.locked_candidates_selected()
        {
            return true;
        }
        self.choices.iter().any(|choice| match choice {
            Choice::Selected(_) => true,
            Choice::New(_, record) => !self.conflicts(record),
        })
    }
}

pub(super) fn solve(
    state: State,
    pending: Pending,
    catalog: &mut Catalog,
    options: &Options,
    locked: &[LockedPreference],
    scope: Scope<'_>,
    loader: &mut dyn FnMut(&str, &VersionReq, &mut Catalog) -> Result<()>,
) -> std::result::Result<State, Failure> {
    // Preserve backtracking on the heap; a forced choice replaces its frame.
    // Process-stack depth is independent of graph width and queued features.
    let mut frames = vec![Frame::new(state, pending)];
    loop {
        let frame = frames.last_mut().unwrap();
        match frame.next(catalog, options, locked, scope, loader) {
            Ok(None) => return Ok(frames.pop().unwrap().state),
            Ok(Some((state, pending))) => {
                let child = Frame::new(state, pending);
                if frame.can_retry() {
                    frames.push(child);
                } else {
                    *frame = child;
                }
            }
            Err(failure) if failure.fatal => return Err(failure),
            Err(failure) => {
                frames.pop();
                let Some(parent) = frames.last_mut() else {
                    return Err(failure);
                };
                parent.last_failure = Some(failure);
            }
        }
    }
}

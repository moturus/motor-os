use super::*;

enum Choice {
    Selected(PackageKey),
    New(PackageKey, Arc<Candidate>),
}

struct Frame {
    state: State,
    queue: VecDeque<Event>,
    event: Option<Event>,
    // Untried candidates in Cargo's order, including selected packages.
    choices: VecDeque<Choice>,
    tried: BTreeSet<PackageKey>,
    // Catalog records for the dependency name when `choices` was ordered.
    ordered_records: Option<usize>,
    preferred: Option<BTreeSet<locked::Identity>>,
    locked_package: Option<PackageKey>,
    allowed: Option<BTreeSet<locked::Identity>>,
    last_failure: Option<Failure>,
}

impl Frame {
    fn new(state: State, queue: VecDeque<Event>) -> Self {
        Self {
            state,
            queue,
            event: None,
            choices: VecDeque::new(),
            tried: BTreeSet::new(),
            ordered_records: None,
            preferred: None,
            locked_package: None,
            allowed: None,
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
    ) -> std::result::Result<Option<(State, VecDeque<Event>)>, Failure> {
        if self.event.is_none() {
            let Some(mut event) = self.queue.pop_front() else {
                return Ok(None);
            };
            let locked_package = scope.locked_package(&event)?;
            self.allowed = scope.locked_dependencies(&event)?.cloned();
            self.preferred = scope.dependency_preferences(&event).cloned();
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
                self.preferred = Some(forced);
            }
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
            if let Some(limit) = options.max_depth
                && event.depth > limit
            {
                return Err(Failure::new(format!(
                    "`{}` exceeds dependency depth {}",
                    event.dependency.package, limit
                )));
            }
            self.locked_package = locked_package.cloned();
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
            let mut queue = self.queue.clone();
            match fulfill(&mut state, &mut queue, event, &key, options, scope) {
                Ok(()) => return Ok(Some((state, queue))),
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
            let key = PackageKey {
                name: record.name.clone(),
                version: record.version.clone(),
                source: record.source.key(),
            };
            records.entry(key).or_insert(record);
        }
        let mut ordered = records
            .into_iter()
            .filter(|(key, _)| {
                !self.tried.contains(key)
                    && self
                        .locked_package
                        .as_ref()
                        .is_none_or(|locked| locked == key)
                    && self
                        .allowed
                        .as_ref()
                        .is_none_or(|allowed| allowed.contains(&locked::Identity::from_key(key)))
            })
            .collect::<Vec<_>>();
        ordered.sort_by(|(left_key, left), (right_key, right)| {
            self.is_preferred(right_key)
                .cmp(&self.is_preferred(left_key))
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
        self.allowed.as_ref().is_some_and(|allowed| {
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

    fn is_preferred(&self, key: &PackageKey) -> bool {
        self.preferred
            .as_ref()
            .is_none_or(|preferred| preferred.contains(&locked::Identity::from_key(key)))
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
        if self.locked_package.is_none()
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
    queue: VecDeque<Event>,
    catalog: &mut Catalog,
    options: &Options,
    locked: &[LockedPreference],
    scope: Scope<'_>,
    loader: &mut dyn FnMut(&str, &VersionReq, &mut Catalog) -> Result<()>,
) -> std::result::Result<State, Failure> {
    // Preserve backtracking on the heap; a forced choice replaces its frame.
    // Process-stack depth is independent of graph width and queued features.
    let mut frames = vec![Frame::new(state, queue)];
    loop {
        let frame = frames.last_mut().unwrap();
        match frame.next(catalog, options, locked, scope, loader) {
            Ok(None) => return Ok(frames.pop().unwrap().state),
            Ok(Some((state, queue))) => {
                let child = Frame::new(state, queue);
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

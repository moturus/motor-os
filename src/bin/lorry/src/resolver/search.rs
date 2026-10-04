use super::*;

enum Choice {
    Selected(PackageKey),
    New(PackageKey, Arc<Candidate>),
}

struct Frame {
    state: State,
    queue: VecDeque<Event>,
    event: Option<Event>,
    choices: VecDeque<Choice>,
    candidates_loaded: bool,
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
            candidates_loaded: false,
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
            if event.depth > options.max_depth {
                return Err(Failure::new(format!(
                    "`{}` exceeds dependency depth {}",
                    event.dependency.package, options.max_depth
                )));
            }
            self.choices.extend(
                self.state
                    .nodes
                    .iter()
                    .filter(|(key, node)| {
                        key.name == event.dependency.package
                            && event.dependency.matches_version(&key.version)
                            && source_matches(&node.record.source, &event.dependency.source)
                            && locked_package.is_none_or(|locked| locked == *key)
                            && self.allowed.as_ref().is_none_or(|allowed| {
                                allowed.contains(&locked::Identity::from_key(key))
                            })
                    })
                    .map(|(key, _)| Choice::Selected(key.clone())),
            );
            self.locked_package = locked_package.cloned();
            self.event = Some(event);
        }
        let event = self.event.as_ref().unwrap();
        loop {
            if self.choices.is_empty() && !self.candidates_loaded {
                // A failed existing selection may load more versions through
                // its children. Query fresh candidates only after that failure.
                self.choices.extend(
                    candidates(catalog, event, options, locked)
                        .into_iter()
                        .filter_map(|record| {
                            let key = PackageKey {
                                name: record.name.clone(),
                                version: record.version.clone(),
                                source: record.source.key(),
                            };
                            self.locked_package
                                .as_ref()
                                .is_none_or(|locked| locked == &key)
                                .then_some((key, record))
                                .filter(|(key, _)| {
                                    self.allowed.as_ref().is_none_or(|allowed| {
                                        allowed.contains(&locked::Identity::from_key(key))
                                    })
                                })
                                .map(|(key, record)| Choice::New(key, Arc::new(record)))
                        }),
                );
                self.candidates_loaded = true;
            }
            let Some(choice) = self.choices.pop_front() else {
                break;
            };
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
                        Node {
                            record,
                            activations: BTreeMap::new(),
                            compile_kinds: BTreeSet::new(),
                            edges: BTreeMap::new(),
                        },
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
        Err(self.last_failure.take().unwrap_or_else(|| {
            Failure::new(format!(
                "no version of `{}` matches `{}`",
                event.dependency.package, event.dependency.requirement
            ))
        }))
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
        if !self.candidates_loaded
            && self.locked_package.is_none()
            && !matches!(
                self.event.as_ref().unwrap().dependency.source,
                RequirementSource::Path(_)
            )
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

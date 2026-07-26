use std::collections::{HashMap, VecDeque};
use std::hash::Hash;

/// Insertion-ordered bounded map.
///
/// Updating a key refreshes its generation. Stale queue entries are skipped
/// during eviction, keeping the public capacity invariant exact without an
/// unbounded secondary index.
#[derive(Clone, Debug)]
pub struct BoundedMap<K, V> {
    capacity: usize,
    generation: u64,
    values: HashMap<K, (V, u64)>,
    order: VecDeque<(K, u64)>,
    evictions: u64,
}

impl<K, V> BoundedMap<K, V>
where
    K: Clone + Eq + Hash,
{
    pub fn new(capacity: usize) -> Self {
        assert!(capacity > 0, "bounded map capacity must be nonzero");
        Self {
            capacity,
            generation: 0,
            values: HashMap::with_capacity(capacity),
            order: VecDeque::with_capacity(capacity),
            evictions: 0,
        }
    }

    pub fn insert(&mut self, key: K, value: V) -> Option<V> {
        self.generation = self.generation.wrapping_add(1);
        let generation = self.generation;
        let old = self
            .values
            .insert(key.clone(), (value, generation))
            .map(|(value, _)| value);
        self.order.push_back((key, generation));
        self.evict_to_capacity();
        old
    }

    pub fn get(&self, key: &K) -> Option<&V> {
        self.values.get(key).map(|(value, _)| value)
    }

    pub fn iter(&self) -> impl Iterator<Item = (&K, &V)> {
        self.values
            .iter()
            .map(|(key, (value, _generation))| (key, value))
    }

    pub fn remove(&mut self, key: &K) -> Option<V> {
        self.values.remove(key).map(|(value, _)| value)
    }

    pub fn len(&self) -> usize {
        self.values.len()
    }

    pub fn is_empty(&self) -> bool {
        self.values.is_empty()
    }

    pub fn capacity(&self) -> usize {
        self.capacity
    }

    pub fn evictions(&self) -> u64 {
        self.evictions
    }

    fn evict_to_capacity(&mut self) {
        while self.values.len() > self.capacity {
            let Some((candidate, generation)) = self.order.pop_front() else {
                break;
            };
            let current = self
                .values
                .get(&candidate)
                .map(|(_, current_generation)| *current_generation);
            if current == Some(generation) {
                self.values.remove(&candidate);
                self.evictions += 1;
            }
        }
        // Refreshes can leave stale nodes. Bound queue overhead to 4x the
        // declared capacity by rebuilding from live generations.
        if self.order.len() > self.capacity.saturating_mul(4) {
            self.order.retain(|(key, generation)| {
                self.values
                    .get(key)
                    .is_some_and(|(_, current)| current == generation)
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn never_exceeds_capacity() {
        let mut map = BoundedMap::new(2);
        map.insert("a", 1);
        map.insert("b", 2);
        map.insert("c", 3);
        assert_eq!(map.len(), 2);
        assert!(map.get(&"a").is_none());
        assert_eq!(map.evictions(), 1);
    }

    #[test]
    fn refreshing_key_does_not_evict_new_value() {
        let mut map = BoundedMap::new(2);
        map.insert("a", 1);
        map.insert("b", 2);
        map.insert("a", 3);
        map.insert("c", 4);
        assert_eq!(map.get(&"a"), Some(&3));
        assert!(map.get(&"b").is_none());
    }
}

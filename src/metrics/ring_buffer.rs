//! Generic circular buffer for time-series metric data.
//!
//! Stores the last N data points at fixed intervals. Used by the
//! MetricsCollector to maintain 24h of history at 1-minute resolution
//! (spec 10-dashboard.md §6.3).

/// Fixed-size circular buffer for time-series data.
///
/// Stores data points in a pre-allocated vector, overwriting the oldest
/// entry when full. All operations are O(1).
pub struct RingBuffer<T: Copy + Default> {
    data: Vec<T>,
    capacity: usize,
    write_pos: usize,
    count: usize,
}

impl<T: Copy + Default> RingBuffer<T> {
    /// Create a new ring buffer with the given capacity.
    ///
    /// All slots are initialized to `T::default()`.
    pub fn new(capacity: usize) -> Self {
        assert!(capacity > 0, "ring buffer capacity must be > 0");
        Self {
            data: vec![T::default(); capacity],
            capacity,
            write_pos: 0,
            count: 0,
        }
    }

    /// Push a new data point, overwriting the oldest if full.
    pub fn push(&mut self, value: T) {
        self.data[self.write_pos] = value;
        self.write_pos = (self.write_pos + 1) % self.capacity;
        if self.count < self.capacity {
            self.count += 1;
        }
    }

    /// Get the most recent data point, if any.
    pub fn latest(&self) -> Option<&T> {
        if self.count == 0 {
            return None;
        }
        let idx = if self.write_pos == 0 {
            self.capacity - 1
        } else {
            self.write_pos - 1
        };
        Some(&self.data[idx])
    }

    /// Iterate over all stored data points in chronological order (oldest first).
    pub fn iter(&self) -> RingBufferIter<'_, T> {
        let start = if self.count < self.capacity {
            0
        } else {
            self.write_pos
        };
        RingBufferIter {
            buffer: self,
            pos: start,
            remaining: self.count,
        }
    }

    /// Get the last `n` data points in chronological order.
    ///
    /// Returns fewer than `n` if the buffer contains fewer entries.
    pub fn last_n(&self, n: usize) -> Vec<T> {
        let take = n.min(self.count);
        if take == 0 {
            return Vec::new();
        }
        let skip = self.count - take;
        self.iter().skip(skip).copied().collect()
    }

    /// Number of data points currently stored.
    pub fn len(&self) -> usize {
        self.count
    }

    /// Whether the buffer is empty.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }
}

/// Iterator over ring buffer entries in chronological order.
pub struct RingBufferIter<'a, T: Copy + Default> {
    buffer: &'a RingBuffer<T>,
    pos: usize,
    remaining: usize,
}

impl<'a, T: Copy + Default> Iterator for RingBufferIter<'a, T> {
    type Item = &'a T;

    fn next(&mut self) -> Option<Self::Item> {
        if self.remaining == 0 {
            return None;
        }
        let item = &self.buffer.data[self.pos];
        self.pos = (self.pos + 1) % self.buffer.capacity;
        self.remaining -= 1;
        Some(item)
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        (self.remaining, Some(self.remaining))
    }
}

impl<'a, T: Copy + Default> ExactSizeIterator for RingBufferIter<'a, T> {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_push_and_latest() {
        let mut buf = RingBuffer::new(3);
        assert!(buf.latest().is_none());
        assert!(buf.is_empty());

        buf.push(10);
        assert_eq!(*buf.latest().unwrap(), 10);
        assert_eq!(buf.len(), 1);

        buf.push(20);
        buf.push(30);
        assert_eq!(*buf.latest().unwrap(), 30);
        assert_eq!(buf.len(), 3);

        // Overflow — oldest (10) gets overwritten
        buf.push(40);
        assert_eq!(*buf.latest().unwrap(), 40);
        assert_eq!(buf.len(), 3);
    }

    #[test]
    fn test_iter_chronological() {
        let mut buf = RingBuffer::new(3);
        buf.push(1);
        buf.push(2);
        buf.push(3);

        let items: Vec<i32> = buf.iter().copied().collect();
        assert_eq!(items, vec![1, 2, 3]);

        // After wrap-around
        buf.push(4);
        buf.push(5);
        let items: Vec<i32> = buf.iter().copied().collect();
        assert_eq!(items, vec![3, 4, 5]);
    }

    #[test]
    fn test_last_n() {
        let mut buf = RingBuffer::new(5);
        for i in 1..=5 {
            buf.push(i);
        }

        assert_eq!(buf.last_n(3), vec![3, 4, 5]);
        assert_eq!(buf.last_n(10), vec![1, 2, 3, 4, 5]);
        assert_eq!(buf.last_n(0), Vec::<i32>::new());
    }
}

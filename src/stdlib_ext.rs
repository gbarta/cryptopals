use std;

// This really should be in the rust standard library
pub trait PartialOrdIterator<A> {
    fn partial_max(&mut self) -> Option<A>;
    fn partial_min(&mut self) -> Option<A>;
}

impl<A: PartialOrd, T: Iterator<A>> PartialOrdIterator<A> for T {
    #[inline]
    fn partial_max(&mut self) -> Option<A> {
        self.fold(None, |max, x| {
            match max {
                None    => Some(x),
                Some(y) => std::cmp::partial_max(x, y)
            }
        })
    }

    #[inline]
    fn partial_min(&mut self) -> Option<A> {
        self.fold(None, |min, x| {
            match min {
                None    => Some(x),
                Some(y) => std::cmp::partial_min(x, y)
            }
        })
    }
}

#[test]
fn test_iterator_partial()
{
    let floats: [f32, ..4] = [0.4,0.3,0.2,0.1];
    assert_eq!(&0.4, floats.iter().partial_max().unwrap());
    assert_eq!(&0.1, floats.iter().partial_min().unwrap());

    let floats_vec: Vec<f64> = vec![1.0,2.0,3.0,4.0];
    assert_eq!(&4.0, floats_vec.iter().partial_max().unwrap());
    assert_eq!(&1.0, floats_vec.iter().partial_min().unwrap());

    let floats_vec2: Vec<f64> = vec![];
    assert_eq!(None, floats_vec2.iter().partial_max());
    assert_eq!(None, floats_vec2.iter().partial_min());
}

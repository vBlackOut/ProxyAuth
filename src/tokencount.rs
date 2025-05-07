use std::collections::HashMap;

#[derive(Debug)]
pub struct CounterToken {
    calls: HashMap<String, usize>,
}

impl CounterToken {
    pub fn new() -> Self {
        Self {
            calls: HashMap::new(),
        }
    }
    
    pub fn record_call<S: Into<String>>(&mut self, id: S) {
        let id = id.into();
        *self.calls.entry(id).or_insert(0) += 1;
    }
    
    pub fn get_count<S: AsRef<str>>(&self, id: S) -> usize {
        *self.calls.get(id.as_ref()).unwrap_or(&0)
    }

   pub fn get_all_tokens(&self) -> Vec<(String, usize)> {
        self.calls
            .iter()
            .map(|(id, count)| (id.clone(), *count))
            .collect()
    }
}
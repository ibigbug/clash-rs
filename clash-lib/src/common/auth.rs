use std::{collections::HashMap, sync::Arc};

pub trait Authenticator {
    fn authenticate(&self, username: &str, password: &str) -> bool;
    fn users(&self) -> Vec<String>;
    fn enabled(&self) -> bool;
}

pub type ThreadSafeAuthenticator = Arc<dyn Authenticator + Send + Sync>;

pub struct User(String, String);

impl User {
    pub fn new(username: String, password: String) -> Self {
        Self(username, password)
    }
}

pub struct PlainAuthenticator {
    store: HashMap<String, String>,
    usernames: Vec<String>,
}

impl PlainAuthenticator {
    pub fn new(users: Vec<User>) -> Self {
        let mut store = HashMap::new();
        let mut usernames = Vec::new();
        for user in users {
            store.insert(user.0.clone(), user.1.clone());
            usernames.push(user.0);
        }
        Self { store, usernames }
    }
}

impl Authenticator for PlainAuthenticator {
    fn authenticate(&self, username: &str, password: &str) -> bool {
        match self.store.get(username) {
            Some(p) => p == password,
            None => false,
        }
    }

    fn users(&self) -> Vec<String> {
        self.usernames.clone()
    }

    fn enabled(&self) -> bool {
        !self.usernames.is_empty()
    }
}

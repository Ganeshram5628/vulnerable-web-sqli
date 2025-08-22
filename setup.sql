CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT,
    password TEXT
);

INSERT INTO users (username, password) VALUES
('admin', 'admin123'),
('guest', 'guest123'),
('test', 'test123');

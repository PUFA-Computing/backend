CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY,
    username VARCHAR(255) NOT NULL,
    password VARCHAR(255) NOT NULL,
    first_name VARCHAR(255) NOT NULL,
    middle_name VARCHAR(255),
    last_name VARCHAR(255) NOT NULL,
    email VARCHAR(255) NOT NULL,
    student_id VARCHAR(255) NOT NULL,
    major VARCHAR(255) NOT NULL,
    profile_picture VARCHAR,
    date_of_birth DATE,
    role_id INT REFERENCES roles(id) NOT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW(),
    year VARCHAR(4) NOT NULL
);
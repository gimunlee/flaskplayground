BEGIN TRANSACTION;
CREATE TABLE `users` (
	`userid`	TEXT NOT NULL UNIQUE,
	`username`	INTEGER NOT NULL UNIQUE,
	`passwd_hash`	TEXT NOT NULL,
	`authority`	INTEGER,
	PRIMARY KEY(`userid`)
);
COMMIT;

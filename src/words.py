words = []
with open("words.txt") as file:
    words = file.readlines()
words = [w.strip() for w in words]

with open("words.rs", "w") as file:
    _ = file.write(
        f"pub const WORDS: [&str; 1024] = [\"{"\",\"".join(words[:1024])}\"];"
    )


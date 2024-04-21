from faker import Faker
from sys import getsizeof

f = Faker()

def generate_unique_names():
    generated_names = set()  # Using a set to ensure uniqueness
    while len(generated_names) < 1000_000:  # Limiting to 1 million unique names
        name = f.name()
        if name not in generated_names:
            generated_names.add((len(generated_names),name))
            yield (len(generated_names),name)

unique_names_generator = generate_unique_names()

# Printing the type and size of the generator
print(type(unique_names_generator))
print(getsizeof(unique_names_generator))

# Testing by printing the first few unique names
for name in unique_names_generator:
    print(name)

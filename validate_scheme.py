import json
import yaml
from jsonschema import exceptions, validate

# Load the schema
with open("schema.json", "r") as f:
    schema = json.load(f)

# Load the data
with open("./config/config.yaml", "r") as f:
    data = yaml.safe_load(f)

# Validate the data
try:
    validate(data, schema)
    print("Validated successfully")
except exceptions.ValidationError as e:
    print(e)
    exit(1)
except exceptions.SchemaError as e:
    print(e)
    exit(1)

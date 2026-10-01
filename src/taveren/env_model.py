"""Build abstract state field descriptions from an environment model.

An environment model is a JSON object with a ``variable_base_addr`` and a list of
``variables``, each with a ``name``, ``address`` (offset from the base), ``size``,
``sort`` (value type) and ``type`` (``input``, ``output``, ``statevar`` or ``config``).
"""


def generate_field_desc(var_info):
    """Return ``(outputs, inputs)``; state variables are tracked as outputs."""
    fields_output = {}
    fields_input = {}
    var_base_addr = var_info["variable_base_addr"]
    for variable in var_info["variables"]:
        addr = (
            var_base_addr + variable["address"]
            if isinstance(var_base_addr, int)
            else int(var_base_addr, 16) + int(variable["address"], 16)
        )
        if "output" in variable["type"] or "statevar" in variable["type"]:
            fields_output[variable["name"]] = (
                addr,
                variable["sort"],
                variable["size"],
            )
        if "input" in variable["type"]:
            fields_input[variable["name"]] = (
                addr,
                variable["sort"],
                variable["size"],
            )

    return fields_output, fields_input


def generate_output_config_desc(data, base_addr: int):
    """Return ``(outputs, configs)``; state variables are tracked as outputs."""
    fields_desc = {}
    config_fields = {}
    for variable in data["variables"]:
        if variable["type"] == "output" or variable["type"] == "statevar":
            fields_desc[variable["name"]] = (
                base_addr + int(variable["address"], 16),
                variable.get("sort", "int"),
                variable["size"],
            )
        elif variable["type"] == "config":
            config_fields[variable["name"]] = (
                base_addr + int(variable["address"], 16),
                variable.get("sort", "int"),
                variable["size"],
            )

    return fields_desc, config_fields

"""Build abstract state field descriptions from an environment model.

An environment model is a JSON object with a ``variable_base_addr`` and a list of
``variables``, each with a ``name``, ``address`` (offset from the base), ``size``,
``sort`` (value type) and ``type`` (``input``, ``output``, ``statevar`` or ``config``).

Examples:
    A minimal environment model, as it would appear in a JSON file:

    >>> env = {
    ...     "variable_base_addr": "0x43B5C0",
    ...     "variables": [
    ...         {"name": "statevar0", "address": "0x18", "size": 1, "sort": "bool", "type": "statevar"},
    ...         {"name": "MOTOR", "address": "0x20", "size": 1, "sort": "bool", "type": "output"},
    ...         {"name": "SENSOR", "address": "0x28", "size": 1, "sort": "bool", "type": "input"},
    ...     ],
    ... }
    >>> outputs, inputs = generate_field_desc(env)
    >>> {name: hex(addr) for name, (addr, _, _) in outputs.items()}
    {'statevar0': '0x43b5d8', 'MOTOR': '0x43b5e0'}
"""


def generate_field_desc(var_info):
    """
    Split an environment model into output and input field descriptions.

    State variables are tracked as outputs, so they become part of every abstract state. Each description is an
    ``(address, sort, size)`` tuple, ready to be passed to :class:`taveren.AbstractStateFields`.

    ``variable_base_addr`` and the per-variable ``address`` may both be ints, or both be hex strings.

    Args:
        var_info: The environment model (see the module documentation).

    Returns:
        A ``(outputs, inputs)`` pair of dicts mapping variable names to ``(address, sort, size)``.

    Examples:
        >>> env = {
        ...     "variable_base_addr": 0x1000,
        ...     "variables": [
        ...         {"name": "VALVE", "address": 0x0, "size": 1, "sort": "bool", "type": "output"},
        ...         {"name": "LEVEL", "address": 0x8, "size": 2, "sort": "int", "type": "input"},
        ...     ],
        ... }
        >>> outputs, inputs = generate_field_desc(env)
        >>> outputs
        {'VALVE': (4096, 'bool', 1)}
        >>> inputs
        {'LEVEL': (4104, 'int', 2)}

        Hex strings are accepted too:

        >>> env["variable_base_addr"] = "0x1000"
        >>> env["variables"][0]["address"] = "0x4"
        >>> env["variables"][1]["address"] = "0x8"
        >>> generate_field_desc(env)[0]
        {'VALVE': (4100, 'bool', 1)}
    """
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
    """
    Split an environment model into output and configuration field descriptions.

    Like :func:`generate_field_desc`, but collects ``config`` variables instead of inputs, and takes the base address
    as an argument. ``sort`` defaults to ``"int"`` when missing. Per-variable addresses must be hex strings.

    Args:
        data: The environment model. Its ``variable_base_addr`` is ignored.
        base_addr: The address that variable offsets are relative to.

    Returns:
        A ``(outputs, configs)`` pair of dicts mapping variable names to ``(address, sort, size)``.

    Examples:
        >>> env = {
        ...     "variables": [
        ...         {"name": "statevar0", "address": "0x0", "size": 1, "type": "statevar"},
        ...         {"name": "TIMEOUT", "address": "0x10", "size": 4, "sort": "int", "type": "config"},
        ...         {"name": "SENSOR", "address": "0x20", "size": 1, "type": "input"},
        ...     ],
        ... }
        >>> outputs, configs = generate_output_config_desc(env, 0x2000)
        >>> outputs
        {'statevar0': (8192, 'int', 1)}
        >>> configs
        {'TIMEOUT': (8208, 'int', 4)}
    """
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

import copy


def generate_onion(message, node_path):
    packaging_order = copy.deepcopy(node_path)
    packaging_order.reverse()
    onion = [message]
    for hop in packaging_order:
        onion.insert(0, hop)

    return onion

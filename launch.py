import node
from tools import BColors

starting_nodes = [("127.0.0.1", 4000), ("127.0.0.2", 4000), ("127.0.0.3", 4000), ("127.0.0.4", 4000)]

TIME_OUT = 10


def start_network():
    """
    Deploy the four kernel nodes of the TOR network
    """
    try:
        west_node = node.Node(starting_nodes[0], True)
        west_node.start()

        north_node = node.Node(starting_nodes[1], False)
        north_node.start()

        east_node = node.Node(starting_nodes[2], False)
        east_node.start()

        south_node = node.Node(starting_nodes[3], False)
        south_node.start()
    except OSError :
        print(f"{BColors.FAIL}failed to start properly, wait a moment before trying again{BColors.ENDC}")
        return 1

    print(f"{BColors.OKGREEN}Launch successful{BColors.ENDC}")


if __name__ == '__main__':
    print(f"{BColors.WARNING}{BColors.BOLD}Starting TOR Network...{BColors.ENDC}")
    start_network()

import copy
import random
import rsa
import tools

contact_list_format = {
    ("127.0.0.1", 4000): ["public_key", True]
}


class Phonebook:
    def __init__(self):
        self.contact_list = {}
        self.exit_nodes = set()

    def get_contact_list(self):
        return self.contact_list

    def get_contacts(self):
        return [contact for contact in self.contact_list]

    def get_contact(self, public_key):
        for contact in self.contact_list:
            if self.contact_list[contact][0] == public_key:
                return contact

    def get_info(self, contact):
        return self.contact_list[contact]

    def update_exit_nodes(self):
        new_exit_nodes = set()
        for contact in self.contact_list:
            if self.contact_list[contact][1]:
                new_exit_nodes.add(contact)

        self.exit_nodes = new_exit_nodes

    def update_contact_list(self, list_of_contact: dict):
        new_contacts = []
        for new_contact in list_of_contact:
            if new_contact not in self.contact_list:
                new_contacts.append(new_contact)
                self.contact_list[new_contact] = list_of_contact[new_contact]

                if self.contact_list[new_contact][1]:
                    self.exit_nodes.add(new_contact)

        self.complete_contacts(new_contacts)

    def get_exit_nodes(self):
        return self.exit_nodes

    def get_updated_exit_nodes(self):
        self.update_exit_nodes()
        return self.exit_nodes

    def complete_contacts(self, addresses: list):
        for contact in addresses:
            if contact in self.contact_list:
                if type(self.contact_list[contact][0]) is not rsa.PublicKey:
                    public_key = tools.request_key(contact)
                    if type(public_key) is rsa.PublicKey:
                        self.contact_list[contact][0] = public_key
                    else:
                        # Communication failed, suppose that node is offline, remove from phonebook
                        del self.contact_list[contact]

    def define_path(self, path_length):
        # tuple in the path list : (("127.0.0.1", 4000), [public_key, is_exit])
        list_of_node = [(contact, self.get_info(contact)) for contact in self.get_contacts()]
        random.shuffle(list_of_node)
        while len(list_of_node) > path_length:
            index = random.randrange(0, len(list_of_node), 1)
            list_of_node.pop(index)

        list_of_exit = list(self.get_updated_exit_nodes())
        if len(list_of_exit) > 0:
            random.shuffle(list_of_exit)
            exit_node = list_of_exit[random.randrange(0, len(list_of_exit), 1)] if len(list_of_exit) > 1 else list_of_exit[0]
            list_of_node.append((exit_node, self.get_info(exit_node)))
        else:
            raise ConnectionError("No exit node were found")

        if exit_node in [node[0] for node in list_of_node[:-1]]:
            list_of_node.remove((exit_node, self.get_info(exit_node)))  # remove first occurrence

        return list_of_node

    def remove_address(self, address):
        self.contact_list.pop(address)

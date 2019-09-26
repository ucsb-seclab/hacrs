from decision_graph.visitation import visit_parent_first
from decision_graph.visitor import Visitor
from decision_graph import ActionsNode


class InteractionExtractor(Visitor):
    def __init__(self):
        super(InteractionExtractor, self).__init__()

        # 1st list: taken constraints
        # 2nd list: not taken constraints
        # 3rd list: influenced output writes
        self.last_interaction_type = 'write'
        self.last_interaction_offsets = []
        self.interaction_info = []

    def _visit_actions_node(self, node, results):
        """

        :param node:
        :type node: ActionsNode
        :param results:
        :type results:
        :return:
        """
        #import ipdb
        #ipdb.set_trace()
        for action in node.actions_info:
            if self.last_interaction_type != action['type'] and len(self.last_interaction_offsets) > 0:
                self.interaction_info.append({'type': self.last_interaction_type,
                                              'offsets': self.last_interaction_offsets})
                self.last_interaction_offsets = []

            assert len(action['addrs']) == 1
            address = action['addrs'][0]
            self.last_interaction_offsets.extend(range(address, address + action['num_bytes']))
            self.last_interaction_type = action['type']

        return [node]

    def _visit_successors_node(self, node, results):
        return [node]

    def _visit_successor_node(self, node, results):
        return [node]

    def finalize(self):
        if len(self.last_interaction_offsets) > 0:
            self.interaction_info.append({'type': self.last_interaction_type,
                                          'offsets': self.last_interaction_offsets})

        return self.interaction_info


def extract_interaction(graph_head):
    extractor = InteractionExtractor()
    visit_parent_first(graph_head, extractor)
    interaction_info = extractor.finalize()
    return interaction_info
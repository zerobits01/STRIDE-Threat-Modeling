from tabulate import tabulate
from enum import Enum


class Mitigations(Enum):
    Spoofing        = {'Origin-Integrity', 'Authentication', 'Signature'}
    Tampering       = {'Data-Integrity', 'Permissions', 'ACL', 'Hash'}
    Repudiation     = {'Auditing', 'log', 'Authentication'}
    InfoDisclosure  = {'Confidentiality', 'Cryptology'}
    DenialofService = {'Availability', 'Quotas', 'Firewalls', 'NGFWs'}
    ElevationofPriv = {'Authorization', 'ACL'}


class Threat:
    
    def __init__(self, S, T, R, I, D, E):
        """this is a class for showing threats and their info

        Args:
            S (bool): Spoofing
            T (bool): Tampering
            R (bool): Repudiation
            I (bool): Information Disclosure
            D (bool): Denial Of Service
            E (bool): Elevation of Priviledge
        """
        self._S = S
        self._T = T
        self._R = R
        self._I = I
        self._D = D
        self._E = E
        self.mitigations_and_countermeasures = set()
        if S == True:
            self.mitigations_and_countermeasures.update(
                Mitigations.Spoofing.value
            )
        if T == True:
            self.mitigations_and_countermeasures.update(
                Mitigations.Tampering.value
            )
        if R == True:
            self.mitigations_and_countermeasures.update(
                Mitigations.Repudiation.value
            )
        if I == True:
            self.mitigations_and_countermeasures.update(
                Mitigations.InfoDisclosure.value
            )
        if D == True:
            self.mitigations_and_countermeasures.update(
                Mitigations.DenialofService.value
            )
        if E == True:
            self.mitigations_and_countermeasures.update(
                Mitigations.ElevationofPriv.value
            )


    @property
    def S(self):
        return self._S

    @S.setter
    def S(self, value):
        if value == True:
            self.mitigations_and_countermeasures.update(
                Mitigations.Spoofing.value
            )
        self._S = value
        
    @property
    def T(self):
        return self._T

    @T.setter
    def T(self, value):
        if value == True:
            self.mitigations_and_countermeasures.update(
                Mitigations.Tampering.value
            )
        self._T = value

    @property
    def R(self):
        return self._R

    @R.setter
    def R(self, value):
        if value == True:
            self.mitigations_and_countermeasures.update(
                Mitigations.Repudiation.value
            )
        self._R = value
        
    @property
    def I(self):
        return self._I

    @I.setter
    def I(self, value):
        if value == True:
            self.mitigations_and_countermeasures.update(
                Mitigations.InfoDisclosure.value
            )
        self._I = value
        
    @property
    def D(self):
        return self._D

    @D.setter
    def D(self, value):
        if value == True:
            self.mitigations_and_countermeasures.update(
                Mitigations.DenialofService.value
            )
        self._D = value
        
    @property
    def E(self):
        return self._E

    @E.setter
    def E(self, value):
        if value == True:
            self.mitigations_and_countermeasures.update(
                Mitigations.ElevationofPriv.value
            )
        self._E = value


    def get_as_list(self):
        return [
            'x' if self._S else '', 
            'x' if self._T else '', 
            'x' if self._R else '', 
            'x' if self._I else '', 
            'x' if self._D else '', 
            'x' if self._E else '',
            self.mitigations_and_countermeasures        
        ]


class STRIDEMatrix:

    def __init__(self, dfd):
        # for each element we add an element with this format:
        '''
            self.processes = [
                {
                    'type': 'type'
                    'name': 'text',
                    *Threat.get_as_list()
                }
            ]
            
            then we write a function to get it in tabular format
        '''
        self.dfd = dfd
        
        self.ids_processes = {}
        self.ids_data_stores = {}        
        self.ids_external_users = {}
        self.ids_flows = {}
        self.ids_boundaries = {}
        self.all_items = {}
        
        for item in self.dfd.processes:
            self.ids_processes[item.attrib['id']] = item
            self.all_items[item.attrib['id']] = item
        for item in self.dfd.data_stores:
            self.all_items[item.attrib['id']] = item
            self.ids_data_stores[item.attrib['id']] = item
        for item in self.dfd.external_users:
            self.all_items[item.attrib['id']] = item
            self.ids_external_users[item.attrib['id']] = item
        for item in self.dfd.flows:
            self.all_items[item.attrib['id']] = item
            self.ids_flows[item.attrib['id']] = item
        for item in self.dfd.boundaries:
            self.ids_boundaries[item.attrib['id']] = item
        print(
            f'b: {self.ids_boundaries}\n',
            f'd: {self.ids_data_stores}\n',
            f'u: {self.ids_external_users}\n',
            f'f: {self.ids_flows}\n',
            f'p: {self.ids_processes}\n',
            f'all: {self.all_items}\n'
        )
        

        self.matrix = []

    # اگر در یک تراست باندری باشند مشکلی نیست
    def __analyze_processes(self,):
        typed = 'process'
        for item in self.dfd.processes:
            spoo = False
            tamp = False
            repu = False
            info = False
            dos  = False
            evel = True
            
            for i, j in self.ids_flows.items():
                if j.attrib['source'] == item.attrib['id']:
                    if self.all_items[j.attrib['target']].attrib['parent'] != item.attrib['parent']:
                        # spoo and repu
                        spoo = True
                        repu = True
                        info = True
                        # tamp if target is file
                        if j.attrib['target'] in self.ids_data_stores:
                            tamp = True
                        # dos if target is process
                        if j.attrib['target'] in self.ids_processes:
                            dos  = True
                        
                if j.attrib['target'] == item.attrib['id']:
                    if self.all_items[j.attrib['source']].attrib['parent'] != item.attrib['parent']:
                        # spoo and repu
                        spoo = True
                        repu = True
                        info = True
                    if j.attrib['source'] in self.ids_processes:
                            dos  = True
            
            t = Threat(
                # S=True, # under all situation
                # T=True, # it has a connection to data-store(src itself dst data-store)
                # R=True, # -
                # I=True, # connection to data-store(src data-store dst process)
                # D=True, # all situation
                # E=True  # all situation
                S=spoo,
                T=tamp,
                R=repu,
                I=info,
                D=dos ,
                E=evel
            )
            self.matrix.append(
                [
                    typed, 
                    item.attrib['value'],
                    *t.get_as_list()
                ]   
            )


    def __analyze_data_stores(self):
        typed = 'data_store'
        for item in self.dfd.data_stores:
            spoo = False
            tamp = False
            repu = False
            info = False
            dos  = False
            evel = False
            
            for i, j in self.ids_flows.items():
                if j.attrib['source'] == item.attrib['id']:
                    if self.all_items[j.attrib['target']].attrib['parent'] != item.attrib['parent']:
                        if j.attrib['target'] in self.ids_processes or \
                            j.attrib['target'] in self.ids_external_users:
                            info = True
                if j.attrib['target'] == item.attrib['id']:
                    if self.all_items[j.attrib['source']].attrib['parent'] != item.attrib['parent']:
                        tamp = True
                        repu = True
                        info = True
                        dos  = True
            t = Threat(
                # S=False,
                # T=True, # if a process connects to it dst is this
                # R=True, # " "
                # I=True, # " "
                # D=True, # " "
                # E=False
                S=spoo,
                T=tamp, # if a process connects to it dst is this
                R=repu, # " "
                I=info, # " "
                D=dos , # " "
                E=evel
            )
            self.matrix.append(
                [
                    typed, 
                    item.attrib['value'],
                    *t.get_as_list()
                ]   
            )


    def __analyze_ext_user(self):
        typed = 'ext_user'
        for item in self.dfd.external_users:
            spoo = False
            tamp = False
            repu = False
            info = False
            dos  = False
            evel = False
            
            for i, j in self.ids_flows.items():
                if j.attrib['source'] == item.attrib['id']:
                    if self.all_items[j.attrib['target']].attrib['parent'] != item.attrib['parent']:
                        spoo = True
                        dos  = True
                        repu = True
                        info = True
                if j.attrib['target'] == item.attrib['id']:
                    if self.all_items[j.attrib['source']].attrib['parent'] != item.attrib['parent']:
                        info = True # direct info or side channels

            t = Threat(
                S=spoo,  # it connects to a process
                T=tamp, # we dont have direct access to data stores
                R=repu,  # it connects to a process
                I=info, # giving info to a process which shouldnt know this
                D=dos ,  # it connects to a process
                E=evel  # no not really
            )
            self.matrix.append(
                [
                    typed, 
                    item.attrib['value'],
                    *t.get_as_list()
                ]   
            )


    def __analyze_flows(self):
        typed = 'flow'
        for item in self.dfd.flows:
            t = Threat(
                S=False,
                T=True,  # -
                R=False, 
                I=True,  # -
                D=True,  # -
                E=False
            )
            self.matrix.append(
                [
                    typed, 
                    item.attrib['value'],
                    *t.get_as_list()
                ]   
            )


    def analyze_stride_matrix_completely(self):
        print(1)
        self.__analyze_processes()
        print(2)
        self.__analyze_data_stores()
        print(3)
        self.__analyze_ext_user()
        print(4)
        self.__analyze_flows()
        return self.print_tabular(self.matrix)


    @staticmethod
    def print_tabular(data: list):
        """printing data in tabular format

        Args:
            data (list of lists): each list item should have 7 parts
            title (str): string title
        """
        headers = [
            'type'.center(10, ' '),
            'items'.center(10, ' '),
            'S'.center(10, ' '),
            'T'.center(10, ' '),
            'R'.center(10, ' '),
            'I'.center(10, ' '),
            'D'.center(10, ' '),
            'E'.center(10, ' '),
            'mitigations and countermesures'
        ]
        return f'{tabulate(data, headers, tablefmt="github")}\n'


def test_tabular():
    data = [
        [
            'item1'.center(10, ' '),
            ''.center(10, ' '),
            'x'.center(10, ' '),
            ''.center(10, ' '),
            'x'.center(10, ' '),
            ''.center(10, ' '),
            'x'.center(10, ' '),
             
        ],
        [
            'item1'.center(10, ' '),
            'x'.center(10, ' '),
            'x'.center(10, ' '),
            'x'.center(10, ' '),
            'x'.center(10, ' '),
            'x'.center(10, ' '),
            'x'.center(10, ' '),
             
        ],
        [
            'item1'.center(10, ' '),
            ''.center(10, ' '),
            ''.center(10, ' '),
            ''.center(10, ' '),
            ''.center(10, ' '),
            ''.center(10, ' '),
            ''.center(10, ' '),
             
        ],
    ]
    print(STRIDEMatrix.print_tabular(data))


if __name__ == "__main__":
    test_tabular()
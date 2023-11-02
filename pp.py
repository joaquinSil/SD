# Pre-proceso: Selecting variables for IDS


import numpy          as np
import inform_gain    as ig
import redundancy_svd as rsvd

def protocolo(i):
    protocolos = np.array(["b'tcp'", "b'udp'", "b'icmp'"])
    u, valores = np.unique(protocolos, return_inverse=True)
    index = protocolos.tolist().index(str(i))

    return (valores[index] + 1)

def servicio(i):
    servicios = np.array(["b'ftp_data'", "b'other'", "b'private'", "b'http'", "b'remote_job'", "b'name'", "b'netbios_ns'", "b'eco_i'", "b'mtp'", "b'telnet'", "b'finger'", "b'domain_u'", "b'supdup'", "b'uucp_path'", "b'Z39_50'", "b'smtp'", "b'csnet_ns'", "b'uucp'", "b'netbios_dgm'", "b'urp_i'", "b'auth'", "b'domain'", "b'ftp'", "b'bgp'", "b'ldap'", "b'ecr_i'", "b'gopher'", "b'vmnet'", "b'systat'", "b'http_443'", "b'efs'", "b'whois'", "b'imap4'", "b'iso_tsap'", "b'echo'", "b'klogin'", "b'link'", "b'sunrpc'", "b'login'", "b'kshell'", "b'sql_net'", "b'time'", "b'hostnames'", "b'exec'", "b'ntp_u'", "b'discard'", "b'nntp'", "b'courier'", "b'ctf'", "b'ssh'", "b'daytime'", "b'shell'", "b'netstat'", "b'pop_3'", "b'nnsp'", "b'IRC'", "b'pop_2'", "b'printer'", "b'tim_i'", "b'pm_dump'", "b'red_i'", "b'netbios_ssn'", "b'rje'", "b'X11'", "b'urh_i'", "b'http_8001'", "b'tftp_u'"])
    u, valores = np.unique(servicios, return_inverse=True)
    index = servicios.tolist().index(str(i))

    return (valores[index] + 1)

def flag(i):
    flags = np.array(["b'SF'", "b'S0'", "b'REJ'", "b'RSTR'", "b'SH'", "b'RSTO'", "b'S1'", "b'RSTOS0'", "b'S3'", "b'S2'", "b'OTH'"])
    u, valores = np.unique(flags, return_inverse=True)
    index = flags.tolist().index(str(i))

    return (valores[index] + 1)

clase = {
    b'normal': 1, b'neptune': 2, b'teardrop': 2, b'smurf': 2, b'pod': 2, b'back': 2,
    b'land': 2, b'apache2': 2, b'processtable': 2, b'mailbomb': 2, b'udpstorm': 2, b'ipsweep': 3,
    b'portsweep': 3, b'nmap': 3, b'satan': 3, b'saint': 3, b'mscan': 3, b'warezclient': 0,
    b'guess_passwd': 0, b'ftp_write': 0, b'multihop': 0, b'rootkit': 0, b'buffer_overflow': 0, b'imap': 0,
    b'warezmaster': 0, b'phf': 0, b'loadmodule':0, b'spy': 0, b'snmpgetattack': 0, b'httptunnel':0,
    b'ps': 0, b'snmpguess': 0, b'named': 0, b'sendmail': 0, b'xterm': 0, b'worm': 0,
    b'xlock': 0, b'perl': 0, b'xsnoop': 0, b'sqlattack': 0
}

conversion = {
    1: lambda i: protocolo(i),
    2: lambda i: servicio(i),
    3: lambda i: flag(i),
    41: lambda i: clase[i]
}
# Load Parameters
def load_config():
    
    param = np.loadtxt("C:/Users/user/Desktop/Sistemas Distribuidos/Tarea P1/PYTHON/cnf_sv.csv", delimiter='\n')
    
    return(param)
# Load data 
def load_data():
    
    data = np.loadtxt("KDDTrain.txt", delimiter=',')
    
    for filas in data:
        for columnas in data:
            if(data[filas][columnas] == 'normal'):
                data[filas][columnas] =1
                
    return(data)

# selecting variables
def select_vars():
	...
	return()

#save results
def save_results():
    ...
    return

#-------------------------------------------------------------------
# Beginning ...
def main():
    param        = load_config()   
    
    print(param)         
    X            = load_data() 
    print(X)  
    #[gain idx  V]= select_vars(X,param)                 
    #save_results(gain,idx,V)
       
if __name__ == '__main__':   
	 main()

#-------------------------------------------------------------------

import socket
import threading
import argparse
import time
from queue import Queue

# portas mais comuns usadas em serviços reais
PORTAS_COMUNS = [21, 22, 25, 53, 80, 110, 139, 143, 443, 445, 3306, 3389, 8080]

# estrutura compartilhada entre threads
resultados = []
lock = threading.Lock()


# entrada do alvo via argumento ou input
def get_target():
    parser = argparse.ArgumentParser(description="Port Scanner")
    parser.add_argument("alvo", nargs='?', help="IP ou domínio")
    args = parser.parse_args()

    if args.alvo:
        return args.alvo

    while True:
        alvo = input("Alvo: ").strip()
        if alvo:
            return alvo
        print("Alvo inválido.")


# testa conexão TCP na porta
def scan_porta(ip, porta, total, index):
    try:
        s = socket.socket()
        s.settimeout(1)

        print(f"[{index}/{total}] Porta {porta}", end="\r")

        if s.connect_ex((ip, porta)) == 0:
            # garante acesso seguro entre threads
            with lock:
                resultados.append(porta)

        s.close()
    except:
        pass


# worker que consome a fila de portas
def worker(ip, fila, total):
    while not fila.empty():
        porta, index = fila.get()
        scan_porta(ip, porta, total, index)
        fila.task_done()


# organiza o scan com fila + threads
def scan(ip):
    fila = Queue()
    total = len(PORTAS_COMUNS)

    for i, p in enumerate(PORTAS_COMUNS, 1):
        fila.put((p, i))

    # múltiplas threads para acelerar o processo
    for _ in range(10):
        t = threading.Thread(target=worker, args=(ip, fila, total))
        t.daemon = True
        t.start()

    fila.join()


def main():
    print("Port Scanner")
    print("-" * 30)

    alvo = get_target()

    # resolve domínio para IP
    try:
        ip = socket.gethostbyname(alvo)
    except:
        print("Erro ao resolver alvo.")
        return

    print(f"Alvo: {alvo} ({ip})\n")

    # mede tempo total do scan
    inicio = time.time()
    scan(ip)
    tempo = round(time.time() - inicio, 2)

    print("\n" + "-" * 30)
    print(f"Tempo: {tempo}s")

    # exibe resultado final
    if resultados:
        print("\nPortas abertas:")
        for porta in sorted(resultados):
            print(f"[+] {porta}")
    else:
        print("\nNenhuma porta aberta.")

    print("-" * 30)


if __name__ == "__main__":
    main()
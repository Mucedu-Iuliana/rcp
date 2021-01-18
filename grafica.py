import tkinter as t  # interfața Python pt GUI = Graphic User Interface
import re
from tkinter import font as tkfont
import socket
from grafica import *
from server import Server
from tkinter import ttk
from tkinter import messagebox
from tkinter import *


class Server_GUI(t.Tk):
    def __init__(self, *args, **kwargs):
        t.Tk.__init__(self, *args, **kwargs)
        self.titlu = tkfont.Font(family='Times', size=12)
        self.buton = tkfont.Font(family='Times', size=11)
        self.text = tkfont.Font(family='Arial', size=11)
        self.title("DHCP SERVER")
        container = t.Frame(self)
        container.pack(side="top", fill=t.BOTH, expand=True)
        container.grid_rowconfigure(0, weight=1)
        container.grid_columnconfigure(0, weight=1)

        self.frames = {}
        self.dhcp_server = Server(self)
        page_name = pagina.__name__
        frame = pagina(parent=container, controller=self)
        self.frames[page_name] = frame
        frame.grid(row=0, column=0, sticky="nsew")

    def actualizare_gama_adrese(self):
        self.frames["pagina"].vizualizare()
        self.frames["pagina"].static_ip_combobox.configure(values=[ip for ip, ip_info in self.dhcp_server.address_pool.items() if ip_info['mac'] is None])
        self.frames["pagina"].release_ip_combobox.configure(values=[ip for ip, ip_info in self.dhcp_server.address_pool.items() if ip_info['mac'] is not None])


class interfata(t.Frame):
    def __init__(self, parent, controller):
        t.Frame.__init__(self, parent, bg="white")
        self.controller = controller

    @staticmethod
    def numar(number, minim=0, maxim=1_000_000_000_000, zero=False):
        import re
        try:
            nr = float(number)
            if zero and nr == 0:
                return True
            if nr <= minim or nr >= maxim:
                return False
        except ValueError:
            return False
        return bool(re.match(r"[\d]+(.\d)?[\d]*", number))


class pagina(interfata):
    def __init__(self, parent, controller):
        interfata.__init__(self, parent, controller)
        self.initializare_fereastra()

    def initializare_fereastra(self, white_bg='white', black_fg='black'):

        address_pool_frame = t.Frame(master=self, bg=white_bg)
        address_pool_frame.pack(side=t.LEFT, fill=t.Y, expand=0)

        Settings_label = t.LabelFrame(address_pool_frame, bg=white_bg, fg=black_fg, font=self.controller.titlu)
        Settings_label.grid(row=0, column=0, padx=10, pady=10, sticky='w')


        server_status = t.Label(Settings_label, text='Alocare IP')
        server_status.grid(row=0, column=1, padx=5, pady=5)
        static_ip_alloc_frame = t.LabelFrame(Settings_label, bg=white_bg, fg=black_fg, font=self.controller.titlu)
        static_ip_alloc_frame.grid(row=1, column=1, padx=5, pady=5, sticky="w")
        t.Label(static_ip_alloc_frame, text='Adresa IP', bg=white_bg, fg=black_fg, font=self.controller.text).grid(row=0, column=0)
        self.static_ip_combobox = ttk.Combobox(static_ip_alloc_frame, width=30, values=[])

        self.static_ip_combobox.grid(row=0, column=1, sticky=t.W, padx=5, pady=5)
        t.Label(static_ip_alloc_frame, text='MAC', bg=white_bg, fg=black_fg, font=self.controller.text).grid(row=1, column=0)
        self.mac_entry = t.Entry(static_ip_alloc_frame, width=30)
        self.mac_entry.grid(row=1, column=1, sticky=t.W, padx=5, pady=5)
        t.Button(static_ip_alloc_frame, text='Seteaza IP', bg=white_bg, fg=black_fg, font=self.controller.buton, command=self.setare_IP).grid(row=2, padx=5, pady=5, columnspan=2)


        server_status = t.Label(Settings_label, text='Eliberare IP')
        server_status.grid(row=2, column=1, padx=5, pady=5)
        release_ip_frame = t.LabelFrame(Settings_label, bg=white_bg, fg=black_fg, font=self.controller.titlu)
        release_ip_frame.grid(row=3, column=1, padx=5, pady=5, sticky="w")
        t.Label(release_ip_frame, text='Adresa IP', bg=white_bg, fg=black_fg, font=self.controller.text).grid(row=0, column=0)
        self.release_ip_combobox = ttk.Combobox(release_ip_frame, width=30, values=[])

        self.release_ip_combobox.grid(row=0, column=1, sticky=t.W, padx=5, pady=5)
        self.mac_entry.grid(row=1, column=1, sticky=t.W, padx=5, pady=5)
        t.Button(release_ip_frame, text='Eliberare adresa', bg=white_bg, fg=black_fg, font=self.controller.buton, command=self.eliberare_IP).grid(row=2, padx=5, pady=5, columnspan=2)


        server_status = t.Label(Settings_label, text='Gama de adrese')
        server_status.grid(row=0, column=0, padx=10, pady=5)
        address_pool_label = t.LabelFrame(Settings_label, bg=white_bg, fg=black_fg, font=self.controller.titlu)
        address_pool_label.grid(row=1, column=0, padx=5, pady=5)

        t.Label(address_pool_label, text='Adresa IP', bg=address_pool_label["bg"], fg=black_fg, font=self.controller.text).grid(row=0, column=0)
        self.ip_initial = t.Entry(address_pool_label, width=30)
        self.ip_initial.grid(row=3, column=0, sticky=t.W, padx=5, pady=5)
        t.Label(address_pool_label, text='Masca retelei', bg=address_pool_label["bg"], fg=black_fg, font=self.controller.text).grid(row=0, column=1)
        self.masca_initiala = ttk.Combobox(address_pool_label, state='readonly', width=35, values=["/{}".format(str(x)) for x in range(16, 31)])
        self.masca_initiala.grid(row=3, column=1, padx=10, pady=10)

        self.masca_initiala.current(13)
        self.set_pool_address_button = t.Button(address_pool_label, text='Setare gama adrese', command=self.setare_gama_adrese, bg=white_bg, fg=black_fg, font=self.controller.buton)
        self.set_pool_address_button.grid(row=4, column=0, padx=5, pady=5)
        self.incarcare_adr = t.IntVar()


        server_status = t.Label(Settings_label, text='Lease time')
        server_status.grid(row=2, column=0, padx=5, pady=5, sticky='w')
        lease_time_label_frame = t.LabelFrame(Settings_label, bg=white_bg, fg=black_fg, font=self.controller.titlu)
        lease_time_label_frame.grid(row=3, column=0, padx=5, pady=5, sticky="w")
        t.Label(lease_time_label_frame, text='Lease Time', bg=address_pool_label["bg"], fg=black_fg, font=self.controller.text).grid(row=1, column=0)
        self.lease_time_entry = ttk.Combobox(lease_time_label_frame, width=27, values=[60, 600, 86400, 604800])  # 1 minut, 10 minute, 1 zi, o saptamana
        self.lease_time_entry.grid(row=1, column=0, sticky=t.W, padx=5, pady=5)
        t.Button(lease_time_label_frame, text='Lease Time', bg=white_bg, fg=black_fg, font=self.controller.buton, command=self.setare_lease_time).grid(row=2, padx=5, pady=5, columnspan=2)


        server_status = t.Label(address_pool_frame, text='Vizualizare gama de adrese')
        server_status.grid(row=2, column=0, padx=10, pady=15)
        address_pool_viewer_label = t.LabelFrame(address_pool_frame, bg=white_bg, fg=black_fg, font=self.controller.titlu)
        address_pool_viewer_label.grid(row=3, column=0, padx=10, pady=5, sticky='w')

        self.ip_address_pool_text = t.Text(address_pool_viewer_label, height=15, width=94, bg=white_bg, fg=black_fg)
        self.ip_address_pool_text.grid(row=0, column=1, sticky=t.N + t.S)

    @staticmethod
    def ipv4(ipv4, masca):
        import ipaddress
        return str(ipaddress.ip_interface(ipv4 + '/' + str(masca)).network).split('/')[0]

    @staticmethod
    def verificare_gama(ip, masca):
        socket.inet_aton(ip)
        if masca == '':
            raise ValueError
        if masca[0] == '/':
            rezultat_masca = int(masca[1:])
        else:
            rezultat_masca = int(masca)
        if rezultat_masca < 1 or rezultat_masca > 32:
            raise ValueError
        return rezultat_masca

    def setare_gama_adrese(self):
        if self.incarcare_adr.get():
            self.masca_initiala.current(self.controller.dhcp_server.masca_retelei - 16)
            self.ip_initial.delete(0, t.END)
            self.ip_initial.insert(0, self.controller.dhcp_server.adresa_inceput)
        else:
            masca = self.masca_initiala.get()
            ip = self.ip_initial.get()
            try:
                rezultat_masca = self.verificare_gama(ip, masca)
                ip_initial = self.ipv4(ip, rezultat_masca)
                self.controller.dhcp_server.configurare_gama_adrese(ip_initial, rezultat_masca)
                self.controller.dhcp_server.gama_adrese()
            except socket.error:
                messagebox.showinfo("Eroare", "Nu se respecta formatul pt IP")
            except ValueError:
                messagebox.showinfo("Eroare", "Nu se respecta formatul pt masca")
            except OSError:
                messagebox.showinfo("Eroare", "Nu se respecta formatul pt IP")

        self.controller.actualizare_gama_adrese()
        self.vizualizare()

    def vizualizare(self):
        masca = self.masca_initiala.get()
        ip = self.ip_initial.get()
        try:
            rezultat_masca = self.verificare_gama(ip, masca)
        except OSError:
            messagebox.showinfo("Eroare", "Nu se respecta formatul pt IP")
            return
        ip_initial = self.ipv4(ip, rezultat_masca)
        address_pool, adresa_difuzie = Server.calculare_adrese(ip_initial, rezultat_masca)

        self.ip_address_pool_text.delete(1.0, t.END)
        self.ip_address_pool_text.insert(t.END, "Adresa retelei : {}\n".format(ip_initial))
        self.ip_address_pool_text.insert(t.END, "Adresa de difuzie : {}\n".format(adresa_difuzie))
        for key, value in address_pool.items():
            self.ip_address_pool_text.insert(t.END, key + '\n')

    def setare_lease_time(self):
        lease_time = self.lease_time_entry.get()
        if not lease_time.isdigit() or not self.numar(lease_time):
            messagebox.showinfo("Eroare", "Numar invalid")
            return
        self.controller.dhcp_server.setare_lease_time(int(lease_time))

    def eliberare_IP(self):
        ip = self.release_ip_combobox.get()
        if ip not in self.controller.dhcp_server.address_pool:
            messagebox.showinfo("Eroare", "IP not in DHCP Server Address Pool")
            return
        ip_list = [ip for ip, ip_info in self.controller.dhcp_server.address_pool.items() if ip_info['mac'] is not None]
        if ip not in ip_list:
            messagebox.showinfo("Eroare", "IP nu a fost inca alocat")
            return
        self.controller.dhcp_server.address_pool.update({ip: {'mac': None, 'time': None}})
        self.vizualizare()
        self.controller.actualizare_gama_adrese()

    def setare_IP(self):
        ip = self.static_ip_combobox.get()
        dict = self.controller.dhcp_server.address_pool
        if ip not in dict:
            messagebox.showinfo("Eroare", "IP-ul nu se afla in gama de adrese")
            return
        if dict[ip]['mac'] is not None:
            messagebox.showinfo("Eroare", "IP deja folosit".format(ip))
            return
        mac_unk = (self.mac_entry.get()).lower()
        mac_checker = lambda mac: re.match("([0-9a-f]{2}[:]){5}([0-9a-f]{2})", mac)
        if mac_checker(mac_unk) is None:
            messagebox.showinfo("Eroare", "Nu se respecta formatul pt MAC")
            return
        if any(mac_unk in ip_info.values() for ip_info in self.controller.dhcp_server.address_pool.values()):
            messagebox.showinfo("Eroare", "MAC asignat altui IP")
            return
        self.controller.dhcp_server.address_pool.update({ip: {'mac': mac_unk, 'time': None}})
        self.controller.dhcp_server.ip_vechi.update({ip: mac_unk})
        self.vizualizare()
        self.controller.actualizare_gama_adrese()

    def vizualizare(self):
        self.ip_address_pool_text.delete(1.0, t.END)
        self.ip_address_pool_text.insert(t.END, "Adresa retelei : ", 'bold_title')
        self.ip_address_pool_text.insert(t.END, "{}\n".format(self.controller.dhcp_server.adresa_inceput), 'text')
        self.ip_address_pool_text.insert(t.END, "Adresa de difuzie ", 'bold_title')
        self.ip_address_pool_text.insert(t.END, "{}\n".format(self.controller.dhcp_server.adresa_difuzie), 'text')
        self.ip_address_pool_text.insert(t.END, "IP\t\tMAC\t\t\tMAC vechi\n", 'bold_title')
        for key, value in self.controller.dhcp_server.address_pool.items():
            self.ip_address_pool_text.insert(t.END, "{}\t\t{}\t\t\t{}\n".format(key, value['mac'], self.controller.dhcp_server.ip_vechi[key]), 'text')

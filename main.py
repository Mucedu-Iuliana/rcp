import grafica


def interfata():
    app = grafica.Server_GUI()
    app.geometry("800x700")
    app.mainloop()


def main():
    interfata()


if __name__ == '__main__':
    main()

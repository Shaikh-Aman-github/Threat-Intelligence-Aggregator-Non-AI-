#main.py
from cli.menu import start_cli
from gui.dashboard import start_gui


def main():

    print("\n" + "=" * 60)
    print(" Threat Intelligence Aggregator ")
    print("=" * 60)

    print("\n1. Command Line Mode")
    print("2. GUI Mode")
    print("3. Exit")

    choice = input("\nSelect Mode: ")

    if choice == "1":
        start_cli()

    elif choice == "2":
        start_gui()

    elif choice == "3":
        print("Exiting...")

    else:
        print("Invalid Choice")


if __name__ == "__main__":
    main()
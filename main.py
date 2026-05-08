import core.modules.msd as msd_module


def run_msd_module():
    file_path = input("Enter path to the target file: ").strip()
    if not file_path:
        print("No file path provided.")
        return

    exiftool_path = input("Enter exiftool executable path (leave blank to use PATH): ").strip() or None

    extractor = msd_module.ExtractMetadata(file_path, exiftool_path=exiftool_path)
    try:
        metadata = extractor.extract_metadata()
    except FileNotFoundError as exc:
        print(f"ExifTool not found: {exc}")
        return
    except Exception as exc:
        print(f"Error reading metadata: {exc}")
        return

    print("\nMetadata:")
    msd_module.print_metadata(metadata)

    action = input("\nChoose an action: [s]et tag, [d]elete sensitive metadata, [n]one: ").strip().lower()
    if action == "s":
        key = input("Enter metadata key: ").strip()
        value = input("Enter metadata value: ").strip()
        save_choice = input("Save metadata change? [y/N]: ").strip().lower()
        if save_choice == "y":
            try:
                extractor.change_metadata(key, value)
                print(f"Updated metadata: {key} = {value}")
            except FileNotFoundError as exc:
                print(f"ExifTool not found: {exc}")
            except Exception as exc:
                print(f"Error updating metadata: {exc}")
        else:
            print("Metadata change not saved.")
    elif action == "d":
        sensitive = extractor.find_sensitive_metadata(metadata)
        if not sensitive:
            print("No sensitive metadata found to delete.")
            return
        print("Sensitive metadata tags found:")
        for key in sensitive:
            print(f" - {key}")
        save_choice = input("Delete sensitive metadata from file? [y/N]: ").strip().lower()
        if save_choice == "y":
            try:
                msd_module.delete_sensitive_metadata(file_path, sensitive.keys(), exiftool_path=exiftool_path)
                print("Sensitive metadata deleted successfully.")
                print("\nMetadata after deletion:")
                metadata_after = extractor.extract_metadata()
                msd_module.print_metadata(metadata_after)
            except FileNotFoundError as exc:
                print(f"ExifTool not found: {exc}")
            except Exception as exc:
                print(f"Error deleting metadata: {exc}")
        else:
            print("No changes saved.")


def get_modules(module):
    if module == "msd":
        run_msd_module()
    else:
        print("Module not found.")


if __name__ == "__main__":
    module_name = input("Enter the module name: ").strip().lower()
    get_modules(module_name)
    
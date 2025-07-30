import os
from pathlib import Path
from ruamel.yaml import YAML

__config_path__ = "config.yml"

class other_util:
    def load_config():
        try:
            yaml = YAML(typ='safe', pure=True)
            with open("config.yml", "r") as file:
                config = yaml.load(file)
            return config
        except FileNotFoundError:
            return None
        
    def find_files_with_extension(folder, extension):
        if not os.path.isdir(folder):
            return []
        return [
            os.path.abspath(os.path.join(folder, f))
            for f in os.listdir(folder)
            if f.endswith(extension)
        ]
        
    def cdms_check(config):
        wv_folder = "./cache/device/wv/"
        pr_folder = "./cache/device/pr/"
    
        wvd_files = other_util.find_files_with_extension(wv_folder, ".wvd")
        prd_files = other_util.find_files_with_extension(pr_folder, ".prd")
    
        result = {
            "wvd": wvd_files,
            "prd": prd_files
        }
    
        if (not wvd_files or not prd_files) or config["cdms"]["widevine"] == "":
            yaml = YAML()
            yaml.preserve_quotes = True
            
            config_path = Path('config.yml')
            
            widevine_available = bool(wvd_files) or config["cdms"]["widevine"] != ""
            playready_available = bool(prd_files) or config["cdms"]["playready"] != ""
            
            if not (widevine_available or playready_available):
                print("Please check whether the WVD/PRD file is located inside `./cache/device/`")
                return None
            
            # Widevine Logic
            if len(wvd_files) == 1 and config["cdms"]["widevine"] == "":
                selected_file = wvd_files[0]
                print(f"Update config to use {os.path.basename(selected_file)} cdm")
                config["cdms"]["widevine"] = selected_file
                with config_path.open('w', encoding='utf-8') as f:
                    yaml.dump(config, f)
            if len(wvd_files) > 1 and config["cdms"]["widevine"] == "":
                print("Available Widevine CDM:")
                for i, path in enumerate(wvd_files, 1):
                    print(f"{i}. {os.path.basename(path)}")
                
                while True:
                    try:
                        choice = int(input("Enter the number of the file you want to use (if you want bypass, just type '0'): "))
                        if choice == 0:
                            selected_file = None
                            return result
                        if 1 <= choice <= len(wvd_files):
                            selected_file = wvd_files[choice - 1]
                            break
                        else:
                            print("Invalid number. Please re-try.")
                    except ValueError:
                        print("Please type number.")
            
                print(f"Update config to use {os.path.basename(selected_file)} cdm")
                config["cdms"]["widevine"] = selected_file
                with config_path.open('w', encoding='utf-8') as f:
                    yaml.dump(config, f)
            # Playready Logic
            if len(prd_files) == 1 and config["cdms"]["playready"] == "":
                selected_file = prd_files[0]
                print(f"Update config to use {os.path.basename(selected_file)} cdm")
                config["cdms"]["playready"] = selected_file
                with config_path.open('w', encoding='utf-8') as f:
                    yaml.dump(config, f)
            if len(prd_files) > 1 and config["cdms"]["playready"] == "":
                print("Available playready CDM:")
                for i, path in enumerate(prd_files, 1):
                    print(f"{i}. {os.path.basename(path)}")
                
                while True:
                    try:
                        choice = int(input("Enter the number of the file you want to use (if you want bypass, just type '0'): "))
                        if choice == 0:
                            selected_file = None
                            return result
                        if 1 <= choice <= len(prd_files):
                            selected_file = prd_files[choice - 1]
                            break
                        else:
                            print("Invalid number. Please re-try.")
                    except ValueError:
                        print("Please type number.")
            
                print(f"Update config to use {os.path.basename(selected_file)} cdm")
                config["cdms"]["playready"] = selected_file
                with config_path.open('w', encoding='utf-8') as f:
                    yaml.dump(config, f)
        return result
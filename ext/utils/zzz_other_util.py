import ruamel.yaml

__config_path__ = "config.yml"

class other_util:
    def load_config():
        try:
            yaml = ruamel.yaml.YAML(typ='safe', pure=True)
            with open("config.yml", "r") as file:
                config = yaml.load(file)
            return config
        except FileNotFoundError:
            return None
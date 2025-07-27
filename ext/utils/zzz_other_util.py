from ruamel import yaml

__config_path__ = "config.yml"

class other_util:
    def load_config():
        try:
            with open('config.yml', 'r') as yml:
                config = yaml.safe_load(yml)
            return config
        except FileNotFoundError:
            return None
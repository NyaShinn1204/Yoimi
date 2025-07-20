import os
import click
import shutil

from ext.util import (path_check, download_command)

__version__ = "2.0.0"

CONTEXT_SETTINGS = dict(help_option_names=['-h', '--help'], ignore_unknown_options=True)

def delete_folder_contents(folder):
    for filename in os.listdir(folder):
        file_path = os.path.join(folder, filename)
        if os.path.isfile(file_path) or os.path.islink(file_path):
            os.unlink(file_path)
        elif os.path.isdir(file_path):
            shutil.rmtree(file_path)

@click.group(context_settings=CONTEXT_SETTINGS, invoke_without_command=True)
@click.option('--version', is_flag=True, help="Show current version")
def cli(version=False):
    if version:
        print('Yoimi v{} - Created NyaShinn1204 based by NoAiOne'.format(__version__))
        exit(0)

@cli.command("download", short_help="Download a video from yuu Supported we(e)bsite")
@click.argument("input", metavar="<URL site>")
@click.option("--username", "-U", required=False, default=None, help="Use username/password to download premium video")
@click.option("--password", "-P", required=False, default=None, help="Use username/password to download premium video")
@click.option("--proxy", "-p", required=False, default=None, metavar="<ip:port/url>", help="Use http(s)/socks5 proxies (please add `socks5://` if you use socks5)")
@click.option("--resolution", "-r", "res", required=False, default="best", help="Resolution to be downloaded (Default: best)")
@click.option("--resolutions", "-R", "resR", is_flag=True, help="Show available resolutions")
@click.option("--output", "-o", required=False, default=None, help="Output filename")
@click.option("--directory", "--d", "--path", required=False, default=None, help="Output directory")
@click.option('--verbose', '-v', is_flag=True, help="Enable verbosity")
@click.option('--random-directory', '-rd', 'use_rd', is_flag=True, default=True, help="Make temp a random directory")



@click.option('--get-subtitle', '-gsub', 'get_sub', is_flag=True, default=False, help="Coming soon")
@click.option('--embed-sub', '-esub', 'embed_sub', is_flag=True, default=False, help="Coming soon")

@click.option('--write-thumbnail', '-wthumb', 'write_thumbnail', is_flag=True, default=False, help="Coming soon")
@click.option('--embed-thumbnail', '-ebthumb', 'embed_thumbnail', is_flag=True, default=False, help="Coming soon")
@click.option('--embed-metadata', '-ebmeta', 'embed_metadata', is_flag=True, default=False, help="Coming soon")
@click.option('--embed-chapters', '-ebchap', 'embed_chapters', is_flag=True, default=False, help="Coming soon")
def main_downloader(input, username, password, proxy, res, resR, output, directory, verbose, use_rd, get_sub, embed_sub, write_thumbnail, embed_thumbnail, embed_metadata, embed_chapters):
    
    command = {
        "email": username, 
        "password": password,
        "proxy": proxy,
        "resolution": res,
        "show_resolution": resR,
        "output_filename": output,
        "output_directory": directory,
        "verbose": verbose,
        "random_directory": use_rd,
        "get_subtitle": get_sub,
        "embed_subtitle": embed_sub,
        "write_thumbnail": write_thumbnail,
        "embed_thumbnail": embed_thumbnail,
        "embed_metadata": embed_metadata,
        "embed_chapter": embed_chapters
    }
    
    
    check_status = path_check(input)
    if check_status == True:
        if os.path.isfile(input):
            with open(input, 'r', encoding='utf-8') as f:
                lines = f.readlines()
                for line in lines:
                    download_command(line.strip(), command)
        else:
            print("Invalid file path.")
            exit(1)
    else:
        download_command(input, command)

if __name__=='__main__':
    cli()
import os
import sys
import yaml
import shutil
import logging
from datetime import datetime

import click
import requests
import subprocess

from common import (__version__, _prepare_yuu_data, get_parser, path_check, version_check, cdms_check, get_yuu_folder, merge_video, mux_video)

CONTEXT_SETTINGS = dict(help_option_names=['-h', '--help'], ignore_unknown_options=True)

def check_command(command):
    try:
        subprocess.run([command], stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
        #print(f"{command} is installed.")
        return True
    except FileNotFoundError:
        #print(f"{command} is not installed.")
        return False
    except subprocess.CalledProcessError:
        #print(f"{command} is installed but an error occurred while checking its version.")
        return True

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
    """
    A simple AbemaTV and other we(e)bsite video downloader
    """
    if version:
        print('Yoimi v{} - Created by NoAiOne and NyaShinn1204'.format(__version__))
        exit(0)

@cli.command("streams", short_help="Check supported website")
def streams_list():
    supported = {
        "AbemaTV": ["No", "No", "Yes (JP)"],
        "Aniplus Asia": ["Yes", "No", "Yes (SEA)"],
        "GYAO!": ["No", "No", "Yes (JP)"],
        "U-Next": ["Yes", "Yes", "Yes (JP)"],
        "DMM-tv": ["Yes", "Yes", "Unknown"],
        "FOD": ["Yes", "Yes", "Unknown"],
        "NHK+": ["No", "Yes", "Unknown"],
        "Anime3rb": ["No", "No", "No"],
        "Crunchyroll": ["No", "Maybe", "Yes (US)"],
        "Jff Theater": ["No", "No", "Yes (US)"],
        "WOWOW": ["Yes", "Yes", "Unknown"],
        "Bandai-Channel": ["No", "Yes", "Unknwon"],
    }

    print('[INFO] Supported website')
    print('{0: <{width}}{1: <{width}}{2: <{width}}{3: <{width}}'.format("   Website", "Need Login?", "Premium Download?", "Proxy Needed?", width=18))
    for k, v_ in supported.items():
        log_, premi_, proxy_ = v_
        print('{0: <{width}}{1: <{width}}{2: <{width}}{3: <{width}}'.format('>> ' + k, log_, premi_, proxy_, width=18))


@cli.command("download", short_help="Download a video from yuu Supported we(e)bsite")
@click.argument("input", metavar="<URL site>")
@click.option("--username", "-U", required=False, default=None, help="Use username/password to download premium video")
@click.option("--password", "-P", required=False, default=None, help="Use username/password to download premium video")
@click.option("--proxy", "-p", required=False, default=None, metavar="<ip:port/url>", help="Use http(s)/socks5 proxies (please add `socks5://` if you use socks5)")
@click.option("--resolution", "-r", "res", required=False, default="best", help="Resolution to be downloaded (Default: best)")
@click.option("--resolutions", "-R", "resR", is_flag=True, help="Show available resolutions")
@click.option("--mux", "-m", required=False, is_flag=True, default=None, help="Mux .ts to .mkv (Need ffmpeg or mkvmerge)")
@click.option("--muxfile", "-mf", required=False, default="mp4", help="Mux .ts to opticial file")
@click.option("--keep-fragments", "-keep", "keep_", is_flag=True, help="Keep downloaded fragment and combined fragment (If muxing) (Default: no)")
@click.option("--output", "-o", required=False, default=None, help="Output filename")
@click.option('--verbose', '-v', is_flag=True, help="Enable verbosity")
@click.option('--random-directory', '-rd', 'use_rd', is_flag=True, default=True, help="Make temp a random directory")
@click.option('--get-niconico-comment', '-gnc', 'use_gnc', is_flag=True, default=False, help="Get Niconico Commment for Title # Unsupported Anime3rb")
@click.option('--only-download-comment', '-odc', 'use_odc', is_flag=True, default=False, help="Only Download Niconico Commment # Unsupported Anime3rb")

# TODO
@click.option('--get-subtitle', '-gsub', 'get_sub', is_flag=True, default=False, help="Coming soon")
@click.option('--embed-sub', '-esub', 'embed_sub', is_flag=True, default=False, help="Coming soon")

# TODO
@click.option('--write-thumbnail', '-wthumb', 'write_thumbnail', is_flag=True, default=False, help="Coming soon")
@click.option('--embed-thumbnail', '-ebthumb', 'embed_thumbnail', is_flag=True, default=False, help="Coming soon")
@click.option('--embed-metadata', '-ebmeta', 'embed_metadata', is_flag=True, default=False, help="Coming soon")
@click.option('--embed-chapters', '-ebchap', 'embed_chapters', is_flag=True, default=False, help="Coming soon")

# TODO: Coming Option list (maybe only available: abema or unext?)
# how to include metadata? idk
# sub is found only availiable nhk+
# "--write-thumbnail" // done for unext
# "--write-description" // ???? description is nani?  これ消して--embed-metadataに結合予定
# "--embed-thumbnail"// fuck you this option, fffmpeg is suck
# "--embed-metadata" // done for unext
# "--embed-subs"     // maybe only availiable for nhk+ (but nkh+ is not done)
# "--embed-chapters" // done for unext
def main_downloader(input, username, password, proxy, res, resR, mux, muxfile, keep_, output, verbose, use_rd, use_gnc, use_odc, get_sub, embed_sub, write_thumbnail, embed_thumbnail, embed_metadata, embed_chapters):
    #print(input, username, password, proxy, res, resR, mux, muxfile, keep_, output, verbose)
    """
    Main command to access downloader
    
    Check supported streams from yuu with `yuu streams`
    """
    
    """
    Main Download command
    """
    def download_command(input):
        yuuParser, site_text = get_parser(input)
        
        if not yuuParser:
            print('Unknown url format')
            exit(1)
        
        sesi = requests.Session()
        
        version_check(sesi)
        
        with open('config.yml', 'r') as yml:
            config = yaml.safe_load(yml)
        return_cdms = cdms_check(config)
        
        if site_text not in ["abemav1", "aniplus", "gyao"]:
            
            if proxy:
                sesi.proxies = {'http': proxy, 'https': proxy}
            #yuu_logger.debug('Using proxy: {}'.format(proxy))
            
            if os.name != 'nt':
                commands = ["aria2c", "ffmpeg"]
            else:
                commands = ["ffmpeg"]
            error_found = False
            for cmd in commands:
                status = check_command(cmd)
                if status == False:
                    print("[!] Requirement to install {}".format(cmd))
                    error_found = True
                    
            #if os.path.exists("l3.wvd"):
            #    pass
            #else:
            #    print("[-] Error: Widevine CDM File (l3.wvd) is not found")
            #    sys.exit(1)
                    
            if error_found:
                sys.exit(1)
            try:
                if verbose:
                    LOG_LEVEL = "DEBUG"
                else:
                    LOG_LEVEL = "INFO"
                    
                if site_text == "Crunchyroll":
                    import tls_client
                    sesi = tls_client.Session(client_identifier="chrome139",random_tls_extension_order=True)
                    
                yuuParser.main_command(sesi, input, username, password, LOG_LEVEL, [__version__, use_rd, use_gnc, use_odc, write_thumbnail, embed_thumbnail, embed_metadata, embed_sub, get_sub, embed_chapters])
            except Exception as error:
                print(error)
        else:
            if site_text == "abemav1":
                input = input.replace("-v1", "")
            fn_log_output = '{f}/yuu_log-{t}.log'.format(f=get_yuu_folder(), t=datetime.today().strftime("%Y-%m-%d_%HH%MM"))
            logging.basicConfig(level=logging.DEBUG,
                                handlers=[logging.FileHandler(fn_log_output, 'a', 'utf-8')],
                                format='%(asctime)s %(name)-1s -- [%(levelname)s]: %(message)s',
                                datefmt='%Y-%m-%d %H:%M:%S')
            yuu_logger = logging.getLogger('yuu')
        
            console = logging.StreamHandler(sys.stdout)
            LOG_LEVEL = logging.INFO
            if verbose:
                LOG_LEVEL = logging.DEBUG
            console.setLevel(LOG_LEVEL)
            formatter1 = logging.Formatter('[%(levelname)s] %(message)s')
            console.setFormatter(formatter1)
            yuu_logger.addHandler(console)
            
            if proxy:
                sesi.proxies = {'http': proxy, 'https': proxy}
            yuu_logger.debug('Using proxy: {}'.format(proxy))
        
            _prepare_yuu_data() # Prepare yuu_download.json
            
            yuuParser = yuuParser(input, sesi)
            formatter3 = logging.Formatter('[%(levelname)s] {}: %(message)s'.format(yuuParser.type))
            yuu_logger.removeHandler(console)
            console.setFormatter(formatter3)
            yuu_logger.addHandler(console)
        
            if yuuParser.authorization_required:
                if username is None and password is None:
                    yuu_logger.warning('Account are required to download from this VOD')
                    exit(1)
                yuu_logger.info('Authenticating')
                result, reason = yuuParser.authorize(username, password)
                if not result:
                    yuu_logger.error('{}'.format(reason))
                    exit(1)
            if username and password and not yuuParser.authorized:
                yuu_logger.info('Authenticating')
                result, reason = yuuParser.authorize(username, password)
                if not result:
                    yuu_logger.error('{}'.format(reason))
                    exit(1)
        
            if not yuuParser.authorized:
                yuu_logger.info('Fetching temporary user token')
                result, reason = yuuParser.get_token()
                if not result:
                    yuu_logger.error('{}'.format(reason))
                    exit(1)
        
            yuu_logger.info('Parsing url')
            outputs, reason = yuuParser.parse(res, resR)
            if not outputs:
                yuu_logger.error('{}'.format(reason))
                exit(1)
            if isinstance(yuuParser.m3u8_url, list):
                m3u8_list = yuuParser.m3u8_url
            else:
                m3u8_list = [yuuParser.m3u8_url]
            if site_text == "unext":
                if isinstance(yuuParser.mpd_file, list):
                    mpd_list = yuuParser.mpd_file
                else:
                    mpd_list = [yuuParser.mpd_file]
            if resR:
                for m3u8 in m3u8_list:
                    yuu_logger.info('Checking available resolution...')
                    avares, reason = yuuParser.resolutions(m3u8)
                    if not avares:
                        yuu_logger.error('{}'.format(reason))
                        continue
                    yuu_logger.info('Available resolution:')
                    yuu_logger.log(0, '{0: <{width}}{1: <{width}}{2: <{width}}{3: <{width}}'.format("   Key", "Resolution", "Video Quality", "Audio Quality", width=16))
                    print('{0: <{width}}{1: <{width}}{2: <{width}}{3: <{width}}'.format("   Key", "Resolution", "Video Quality", "Audio Quality", width=16))
                    for res in avares:
                        r_c, wxh = res
                        vidq, audq = yuuParser.resolution_data[r_c]
                        yuu_logger.log(0, '{0: <{width}}{1: <{width}}{2: <{width}}{3: <{width}}'.format('>> ' + r_c, wxh, vidq, audq, width=16))
                        print('{0: <{width}}{1: <{width}}{2: <{width}}{3: <{width}}'.format('>> ' + r_c, wxh, vidq, audq, width=16))
                exit(0)
        
            if yuuParser.resolution != res and res not in ['best', 'worst']:
                yuu_logger.warn('Resolution {} are not available'.format(res))
                yuu_logger.warn('Switching to {}'.format(yuuParser.resolution))
                res = yuuParser.resolution
        
            if isinstance(outputs, str):
                outputs = [outputs]
        
            formatter2 = logging.Formatter('[%(levelname)s][DOWN] {}: %(message)s'.format(yuuParser.type))
            yuu_logger.removeHandler(console)
            console.setFormatter(formatter2)
            yuu_logger.addHandler(console)
        
            yuu_logger.info('Starting downloader...')
            yuu_logger.info('Total files that will be downloaded: {}'.format(len(outputs)))
        
            # Initialize Download Process
            yuuDownloader = yuuParser.get_downloader()
            temp_dir = yuuDownloader.temporary_folder
            illegalchar = ['/', '<', '>', ':', '"', '\\', '|', '?', '*'] # https://docs.microsoft.com/en-us/windows/desktop/FileIO/naming-a-file
            for pos, _out_ in enumerate(outputs):
                yuu_logger.info('Parsing m3u8 and fetching video key for files no {}'.format(pos+1))
                files, iv, ticket, reason = yuuParser.parse_m3u8(m3u8_list[pos])
                #print(files, iv, ticket, reason)
                _out_ = yuuParser.check_output(output, _out_)
                
                if muxfile not in ["mp4", "mkv", "ts"]:
                    yuu_logger.error('Failed Check file extension: {}'.format(muxfile))
                    exit(0)
        
                for char in illegalchar:
                    _out_ = _out_.replace(char, '_')
        
                if not files:
                    yuu_logger.error('{}'.format(reason))
                    continue
                key, reason = yuuParser.get_video_key(ticket)
                if not key:
                    yuu_logger.error('{}'.format(reason))
                    continue
        
                yuu_logger.info('Output: {}'.format(_out_))
                yuu_logger.info('Resolution: {}'.format(yuuParser.resolution))
                yuu_logger.info('Estimated file size: {} MiB'.format(yuuParser.est_filesize))
                
                if mux:
                    yuu_logger.info('Mux file extension: {}'.format(muxfile))
        
                if yuuDownloader.merge: # Workaround for stream that don't use .m3u8
                    dl_list = yuuDownloader.download_chunk(files, key, iv)
                    if not dl_list:
                        delete_folder_contents(temp_dir)
                        continue
                else:
                    yuuDownloader.download_chunk(files, _out_)
                    if mux:
                        yuu_logger.info('Muxing video')
                        mux_video(_out_, muxfile)
                if yuuDownloader.merge:
                    yuu_logger.info('Finished download')
                    yuu_logger.info('Merging video')
                    merge_video(dl_list, _out_)
                    if not keep_:
                        delete_folder_contents(temp_dir)
                if mux:
                    if os.path.isfile(_out_):
                        yuu_logger.info('Muxing video')
                        result = mux_video(_out_, muxfile)
                        if not result:
                            yuu_logger.warn('There\'s no available muxers that can be used, skipping...')
                            mux = False # Automatically set to False so it doesn't spam the user
                        elif result and os.path.isfile(result):
                            if not keep_:
                                os.remove(_out_)
                            _out_ = result
                yuu_logger.info('Finished download {}'.format(_out_))
            if not keep_:
                shutil.rmtree(temp_dir)
            exit(0)
    
    check_status = path_check(input)
    if check_status == True:
        if os.path.isfile(input):
            with open(input, 'r', encoding='utf-8') as f:
                lines = f.readlines()
                for line in lines:
                    #print(line.strip())
                    download_command(line.strip())
        else:
            print("Invalid file path.")
            exit(1)
    else:
        download_command(input)


if __name__=='__main__':
    cli()

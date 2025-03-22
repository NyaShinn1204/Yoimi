import os
import parser as parser

parser_for_mpd = parser.global_parser()

mpd_directory = "./mpd_text"
mpd_text = ""

for filename in os.listdir(mpd_directory):
    if filename.endswith(".mpd"):
        with open(os.path.join(mpd_directory, filename), "r", encoding="utf-8") as file:
            mpd_text = file.read() + "\n"
        print(str(parser_for_mpd.mpd_parser(mpd_text))+"\n\n")
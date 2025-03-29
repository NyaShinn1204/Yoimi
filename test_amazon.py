from ext import amazon as amazon_dl

import requests

# 1080の時は SDR
# 2160の時は HDR

amazon_dl.main_command(requests.Session(), "https://www.amazon.co.jp/gp/video/detail/B0CHHPLWM5/ref=atv_hm_hom_c_lW5Kly_brws_2_1?jic=8%7CEgRzdm9k", "", "", "DEBUG", 1080, "SDR", True)

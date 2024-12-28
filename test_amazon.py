from ext import amazon as amazon_dl

import requests

amazon_dl.main_command(requests.session(), "https://www.amazon.co.jp/gp/video/detail/B0CHHPLWM5/ref=atv_hm_hom_c_lW5Kly_brws_2_1?jic=8%7CEgRzdm9k", "", "", "DEBUG")
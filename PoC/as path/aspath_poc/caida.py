"""Get the real CAIDA AS-relationship file (public data, free)."""
import glob, os, re, sys, urllib.request

URL = "https://data.caida.org/datasets/as-relationships/serial-2/"
DIR = "data"
PATTERN = re.compile(r"(\d{8}\.as-rel2\.txt\.bz2)")


def newest(index_html):
    names = PATTERN.findall(index_html or "")
    return max(names) if names else None


def local(folder=DIR):
    files = glob.glob(os.path.join(folder, "*.as-rel2.txt.bz2")) + glob.glob(os.path.join(folder, "*.as-rel2.txt"))
    return max(files, key=os.path.basename) if files else None


def _get(url):
    return urllib.request.urlopen(urllib.request.Request(url, headers={"User-Agent": "fyp-aspath-poc"}), timeout=120)


def download(folder=DIR):
    os.makedirs(folder, exist_ok=True)
    try:
        name = newest(_get(URL).read().decode("utf-8", "replace"))
    except Exception as e:
        sys.exit(f"Could not reach CAIDA ({type(e).__name__}: {e}).\nDownload the newest *.as-rel2.txt.bz2 by hand from {URL} into the folder '{folder}'.")
    if not name:
        sys.exit(f"No *.as-rel2.txt.bz2 found in the listing at {URL}. Download one by hand into '{folder}'.")
    dest = os.path.join(folder, name)
    if os.path.exists(dest):
        print("already there:", dest)
    else:
        print(f"downloading {URL}{name} ...", flush=True)
        tmp = dest + ".part"
        try:
            with _get(URL + name) as r, open(tmp, "wb") as f:
                while True:
                    chunk = r.read(1 << 16)
                    if not chunk:
                        break
                    f.write(chunk)
        except Exception as e:
            if os.path.exists(tmp):
                os.remove(tmp)
            sys.exit(f"Download failed ({type(e).__name__}: {e}).")
        os.replace(tmp, dest)
    from asrel import ASRel
    r = ASRel(dest)
    print(f"saved {dest}: {len(r.rel):,} AS links loaded. Cite: The CAIDA AS Relationships Dataset, {name[:8]}, https://www.caida.org/catalog/datasets/as-relationships/")
    return dest
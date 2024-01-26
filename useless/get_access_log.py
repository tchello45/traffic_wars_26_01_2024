def get_access_log(path:str="/var/log/nginx/access.log"):
    lines = []
    with open(path) as f:
        for line in f:
            lines.append(line)
    return lines
def last_line_number(path:str="/var/log/nginx/access.log"):
    with open(path) as f:
        lines = f.readlines()
    return len(lines)
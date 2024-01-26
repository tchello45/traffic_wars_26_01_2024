import get_access_log
import check_ip
old_start_line = get_access_log.last_line_number()
while True:
    end_line = get_access_log.last_line_number()
    lines = get_access_log.get_access_log()
    #--------------------------------------------------------------------------
    for line in lines[old_start_line:end_line]:
        ip = line.split(" ")[0]
        check_ip.check_ip(ip)
        

    old_start_line = end_line

    
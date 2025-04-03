Firewall rule and db 
Need gui and controller
Starting to write the project report now.

+------------------------+
|        View (UI)       |
|------------------------|
| - mainwindow.py        |
| - rule_dialog.py       |
|                        |
| Hiển thị bảng rule,    |
| nhận sự kiện từ người dùng |
+-----------+------------+
            |
            v
+-----------+------------+
|      Controller         |
|------------------------|
| - Xử lý logic sự kiện   |
| - Gọi Model khi cần     |
| - Cập nhật View         |
+-----------+------------+
            |
     gọi hàm từ Model
            v
+-----------+------------+
|         Model           |
|------------------------|
| - firewall_rules.py     |
|     (tương tác PowerShell) |
| - firewall_db.py        |
|     (SQLite database)   |
+------------------------+

                 |
                 v
       +---------------------+
       | Windows Firewall API|
       +---------------------+

       +---------------------+
       | SQLite (.db file)   |
       +---------------------+


from flask import send_file

from datetime import datetime, timedelta
from dateutil.relativedelta import relativedelta

class DateRange:
    TIME_RANGES = {
        'this_week': '本周',
        'last_week': '上周',
        'this_month': '本月',
        'this_quarter': '本季度',
        'this_year': '本年',
    }

    today = datetime.today().date()

    def __init__(self):
        DateRange.today = datetime.today().date()


    @staticmethod
    def this_week():
        start_date = DateRange.today - timedelta(days=DateRange.today.weekday())  # 本周一
        end_date = DateRange.today  # 今天
        return start_date, end_date

    @staticmethod
    def last_week():
        start_date = DateRange.today - timedelta(days=DateRange.today.weekday() + 7)  # 上周一
        end_date = start_date + timedelta(days=6)  # 上周日
        return start_date, end_date

    @staticmethod
    def last_n_days(n):
        start_date = DateRange.today - timedelta(days=n)
        end_date = DateRange.today
        return start_date, end_date

    @staticmethod
    def this_month():
        start_date = (DateRange.today.replace(day=1) - relativedelta(months=0)).replace(day=1)
        end_date = DateRange.today
        return start_date, end_date
    
    @staticmethod
    def this_quarter():
        current_month = DateRange.today.month
        start_month = (current_month - 1) // 3 * 3 + 1  # 计算当前季度的开始月份
        start_date = datetime(DateRange.today.year, start_month, 1).date()

        # 计算季度结束日期
        if start_month == 1:
            end_date = datetime(DateRange.today.year, 3, 31).date()
        elif start_month == 4:
            end_date = datetime(DateRange.today.year, 6, 30).date()
        elif start_month == 7:
            end_date = datetime(DateRange.today.year, 9, 30).date()
        else:  # start_month == 10
            end_date = datetime(DateRange.today.year, 12, 31).date()

        return start_date, end_date


    @staticmethod
    def this_year():
        start_date = datetime(DateRange.today.year, 1, 1).date()
        end_date = DateRange.today  # 到今天
        return start_date, end_date
    
    @staticmethod
    def get_range(time_range):

        # 创建时间范围映射字典
        time_range_methods = {
            'this_week': DateRange.this_week,
            'last_week': DateRange.last_week,
            'this_month': DateRange.this_month,
            'this_quarter': DateRange.this_quarter,
            'this_year': DateRange.this_year,
        }

        # 计算日期范围
        if time_range in time_range_methods:
            start_date, end_date = time_range_methods[time_range]()  # 调用相应的方法
        else:
            start_date, end_date = DateRange.this_year()  # 默认返回本年的数据
        return start_date, end_date

    @staticmethod
    def print_info():
        print(DateRange.this_week())
        print(DateRange.last_week())
        print(DateRange.this_month())
        print(DateRange.last_n_days(14))
        print(DateRange.this_quarter())
        print(DateRange.this_year())


from openpyxl import Workbook
from openpyxl.styles import Font, Color, Alignment, PatternFill, Border, Side
from io import BytesIO
import io
from datetime import datetime, timedelta
from bs4 import BeautifulSoup

# 将 HTML 转换为纯文本的函数，改进 convert_list
def html_to_text(html_content):
    soup = BeautifulSoup(html_content, 'html.parser')

    result = []
    
    # 处理有序或无序列表，使用递归处理层级
    def convert_list(list_tag, level_prefix="", ordered=True):
        for idx, li in enumerate(list_tag.find_all('li', recursive=False), 1):
            # 确定当前前缀：有序列表用数字前缀，无序列表用符号前缀
            current_prefix = f"{level_prefix}{idx}." if ordered else f"{level_prefix}-"
            
            # 提取当前 <li> 的直接文本（不包含嵌套的子元素）
            main_text = li.find(text=True, recursive=False)
            main_text = main_text.strip() if main_text else ''
            result.append(f"{current_prefix} {main_text}")
            
            # 递归处理嵌套的有序或无序列表
            nested_ul = li.find('ul')
            nested_ol = li.find('ol')
            if nested_ul:
                convert_list(nested_ul, level_prefix + "    ", ordered=False)  # 传入当前缩进和无序标记
            elif nested_ol:
                convert_list(nested_ol, level_prefix + "    ", ordered=True)  # 传入当前缩进和有序标记
    
    # 处理段落和其他标签
    for element in soup.contents:
        if element.name == 'ol':
            convert_list(element, ordered=True)  # 有序列表
        elif element.name == 'ul':
            convert_list(element, ordered=False)  # 无序列表
        elif element.name == 'p' and element.get_text(strip=True):
            result.append(element.get_text(strip=True))
        elif element.name == 'strong':
            result.append(f"**{element.get_text(strip=True)}**")  # 加粗的文本
        else:
            result.append(element.get_text(strip=True))

    return "\n".join(result)



# 辅助函数：获取周的起始日期和结束日期
def get_week_date_range(year, week):
    # 根据ISO日历计算周的开始日期（周一）和结束日期（周日）
    start_date = datetime.strptime(f"{year}-W{week}-1", "%Y-W%W-%w")
    end_date = start_date + timedelta(days=6)
    return f"{start_date.strftime('%Y-%m-%d')}\n-\n{end_date.strftime('%Y-%m-%d')}"


class RecordDownloader:

    @staticmethod
    def download(user_weekly_data, all_weeks, filename):
        # 创建工作簿
        wb = Workbook()
        ws = wb.active
        ws.title = '软件开发组周报'

        # 表头样式：深色背景 + 加粗字体
        header_fill = PatternFill(start_color="808080", end_color="808080", fill_type="solid")  # 深灰色
        header_font = Font(bold=True, color="FFFFFF")  # 白色字体

        # 按年份和周排序，并转换为日期范围格式
        all_weeks = sorted(all_weeks, key=lambda x: (x[0], x[1]), reverse=True)
        headers = ['姓名'] + [get_week_date_range(year, week) for year, week in all_weeks]
        ws.append(headers)

        # 填充数据
        for username, weekly_data in user_weekly_data.items():
            row = [username]
            
            # 按列顺序填充每周的记录
            for week in all_weeks:
                content = weekly_data.get(week, "")  # 如果没有记录则为空
                row.append(html_to_text(content))
            
            ws.append(row)

        # 设置第一行加粗
        for cell in ws['1']:  # '1' 列表示第一行
            cell.font = header_font
            cell.fill = header_fill
            cell.alignment = Alignment(horizontal="center", vertical="center", wrap_text=True)


        # 数据行样式：隔行变色
        light_fill = PatternFill(start_color="EAEAEA", end_color="EAEAEA", fill_type="solid")  # 浅灰色
        for row_idx, row in enumerate(ws.iter_rows(min_row=2, max_col=ws.max_column, max_row=ws.max_row), start=2):
            for cell in row:
                if row_idx % 2 == 0:  # 偶数行设置背景色
                    cell.fill = light_fill
                cell.alignment = Alignment(horizontal="left", wrap_text=True) # 启用单元格内换行

        # 设置第一列加粗
        for cell in ws['A']:  # 'A' 列表示第一列
            cell.font = Font(bold=True)
            cell.alignment = Alignment(horizontal="center", vertical="center", wrap_text=True)

        # 设置所有列宽
        for col in ws.columns:
            max_length = 15
            column = col[0].column_letter  # 获取列字母
            ws.column_dimensions[column].width = max_length

        # 设置边框样式
        thin_border = Border(
            left=Side(style="thin"),
            right=Side(style="thin"),
            top=Side(style="thin"),
            bottom=Side(style="thin")
        )

        for row in ws.iter_rows(min_row=1, max_col=ws.max_column, max_row=ws.max_row):
            for cell in row:
                cell.border = thin_border
                

        # 将工作簿保存到内存中
        output = BytesIO()
        wb.save(output)
        output.seek(0)

        # 将 CSV 文件发送给客户端下载
        return send_file(
            output,  # 转换为字节流
            mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
            as_attachment=True,
            download_name=filename
        )


if __name__ == '__main__':
    dr = DateRange()
    dr.print_info()

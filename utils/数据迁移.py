# -*- coding: utf-8 -*-
"""
@author: hanyanling
@date: 2024/1/15 22:09
@email:
---------
@summary:
"""

from feapder.db.mysqldb import MysqlDB
class DataMigration:
    def __init__(self):
        self.__db_maps = {}

    def set_db(self, name, ip, port, user, pwd):
        self.__db_maps[name] = MysqlDB(ip=ip, port=port, user_name=user, user_pass=pwd)

    def get_db(self, name):
        return self.__db_maps.get(name)

    def process_data(self, datas):
        # TODO 这里处理数据
        pass

    def upsert_data(self, datas):
        # TODO 更新或插入数据
        pass

    def del_data(self, datas):
        # TODO 删除数据
        pass

if __name__ == '__main__':
    data_migration = DataMigration()
    data_migration.set_db()


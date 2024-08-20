# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
__copyright__ = ('Copyright Amazon.com, Inc. or its affiliates. '
                 'All Rights Reserved.')
__version__ = '2.10.3'
__license__ = 'MIT-0'
__author__ = 'Akihiro Nakajima'
__url__ = 'https://github.com/aws-samples/siem-on-amazon-opensearch-service'

import bz2
import copy
import gzip
import hashlib
import io
import json
import re
import zipfile
from datetime import datetime, timedelta, timezone
from functools import cached_property
from typing import Tuple

from aws_lambda_powertools import Logger

from siem import user_agent, utils
from siem.fileformat_base import FileFormatBase
from siem.fileformat_cef import FileFormatCef
from siem.fileformat_csv import FileFormatCsv
from siem.fileformat_json import FileFormatJson
from siem.fileformat_multiline import FileFormatMultiline
from siem.fileformat_parquet import FileFormatParquet
from siem.fileformat_text import FileFormatText
from siem.fileformat_winevtxml import FileFormatWinEvtXml
from siem.fileformat_xml import FileFormatXml

logger = Logger(child=True)


class LogS3:
    """取得した一連のログファイルから表層的な情報を取得し、個々のログを返す.

    圧縮の有無の判断、ログ種類を判断、フォーマットの判断をして
    最後に、生ファイルを個々のログに分割してリスト型として返す
    """
    def __init__(self, record, s3bucket, s3key, logtype, logconfig, s3_client,
                 sqs_queue):
        self.error_logs_count = 0
        self.record = record
        self.logtype = logtype
        self.logconfig = logconfig
        self.s3_client = s3_client
        self.sqs_queue = sqs_queue
        self.s3bucket = s3bucket
        self.s3key = s3key
        self.s3obj_size = self.s3obj_size
        self.excluded_log_count = 0
        self.counted_log_count = 0

        self.loggroup = None
        self.logstream = None

        logger.info(self.startmsg())
        if self.is_ignored:
            return None
        self.via_cwl = self.logconfig['via_cwl']
        self.via_firelens = self.logconfig['via_firelens']
        self.file_format = self.logconfig['file_format']
        self.max_log_count = self.logconfig['max_log_count']
        self.__rawdata = self.extract_rawdata_from_s3obj()
        if self.__rawdata:
            self.__file_timestamp = self.extract_file_timestamp()
            self.rawfile_instacne = self.set_rawfile_instance()

    def __iter__(self):
        if self.is_ignored:
            return
        if self.log_count > self.max_log_count:
            if self.sqs_queue:
                metadata = self.split_logs(self.log_count, self.max_log_count)
                sent_count = self.send_meta_to_sqs(metadata)
                self.is_ignored = True
                self.total_log_count = 0
                self.ignored_reason = (f'Log file was split into {sent_count}'
                                       f' pieces and sent to SQS.')
                return

        yield from self.logdata_generator()

    ###########################################################################
    # Property
    ###########################################################################
    @cached_property
    def is_ignored(self):
        # normal reason
        if self.s3key[-1] == '/':
            self.ignored_reason = f'this s3 key is just path, {self.s3key}'
            return True
        elif 'unknown' in self.logtype:
            # 対応していないlogtypeはunknownになる。その場合は処理をスキップさせる
            self.ignored_reason = f'unknown log type in S3 key, {self.s3key}'
            return True
        re_s3_key_ignored = self.logconfig['s3_key_ignored']
        if re_s3_key_ignored:
            m = re_s3_key_ignored.search(self.s3key)
            if m:
                self.ignored_reason = (fr'"s3_key_ignored" {re_s3_key_ignored}'
                                       fr' matched with {self.s3key}')
                return True

        # critical reson
        if not self.logconfig.get('file_format'):
            self.critical_reason = (
                f'of unknown file format for {self.logtype}. '
                'Configure file_format in user/ini')
            return True
        elif not self.logconfig.get('index_name'):
            self.critical_reason = (
                f'of no index_name for {self.logtype}. '
                'Configure index_name in user/ini')
            return True

        return False

    @cached_property
    def log_count(self):
        if self.end_number == 0:
            if self.via_cwl:
                log_count = self.log_count_cwl_log()
            elif self.via_firelens:
                log_count = len(self.rawdata.readlines())
            else:
                # text, json, csv, winevtxml, multiline, xml, parquet
                log_count = self.rawfile_instacne.log_count
            if log_count == 0:
                self.is_ignored = True
                self.ignored_reason = (
                    'there are not any valid logs in S3 object')
            return log_count
        else:
            return (self.end_number - self.start_number + 1)

    @property
    def rawdata(self):
        self.__rawdata.seek(0)
        return self.__rawdata

    @cached_property
    def accountid(self):
        s3key_accountid = utils.extract_aws_account_from_text(self.s3key)
        if s3key_accountid:
            return s3key_accountid
        else:
            return None

    @cached_property
    def region(self):
        s3key_region = utils.extract_aws_region_from_text(self.s3key)
        if s3key_region:
            return s3key_region
        else:
            return None

    @cached_property
    def start_number(self):
        try:
            return int(self.record['siem']['start_number'])
        except KeyError:
            return 0

    @cached_property
    def end_number(self):
        try:
            return int(self.record['siem']['end_number'])
        except KeyError:
            return 0

    @cached_property
    def s3obj_size(self):
        if 's3' in self.record:
            _s3obj_size = self.record['s3']['object'].get('size', 0)
        elif 'detail' in self.record:
            _s3obj_size = self.record['detail']['object'].get('size', 0)
        return _s3obj_size

    ###########################################################################
    # Method/Function
    ###########################################################################
    def startmsg(self):
        startmsg = {'msg': 'Invoked es-loader', 's3_bucket': self.s3bucket,
                    's3_key': self.s3key, 'logtype': self.logtype,
                    'start_number': self.start_number,
                    'end_number': self.end_number}
        return startmsg

    def set_rawfile_instance(self):
        if self.file_format == 'text':
            return FileFormatText(self.rawdata, self.logconfig, self.logtype)
        elif self.file_format == 'json':
            return FileFormatJson(self.rawdata, self.logconfig, self.logtype)
        elif self.file_format == 'csv':
            return FileFormatCsv(self.rawdata, self.logconfig, self.logtype)
        elif self.file_format == 'winevtxml':
            return FileFormatWinEvtXml(
                self.rawdata, self.logconfig, self.logtype)
        elif self.file_format == 'multiline':
            return FileFormatMultiline(
                self.rawdata, self.logconfig, self.logtype)
        elif self.file_format == 'parquet':
            return FileFormatParquet(
                self.rawdata, self.logconfig, self.logtype)
        elif self.file_format == 'xml':
            return FileFormatXml(self.rawdata, self.logconfig, self.logtype)
        elif self.file_format == 'cef':
            return FileFormatCef(self.rawdata, self.logconfig, self.logtype)
        elif not self.file_format:
            self.is_ignored = True
            self.ignored_reason = (
                f'Skipped because there is no file format of {self.logtype}'
                'in user.ini')
        else:
            return FileFormatBase(self.rawdata, self.logconfig, self.logtype)

    def logdata_generator(self) -> Tuple[str, dict, dict]:
        logmeta = {}
        if self.__file_timestamp:
            logmeta['file_timestamp'] = self.__file_timestamp
        start, end = self.set_start_end_position()
        self.total_log_count = end - start + 1

        if self.via_cwl:
            for lograw, logmeta in self.extract_cwl_log(start, end, logmeta):
                logdict = self.rawfile_instacne.convert_lograw_to_dict(lograw)
                if isinstance(logdict, dict):
                    if self.logconfig["json_delimiter"]:
                        # multiple events in 1 json
                        for record in utils.value_from_nesteddict_by_dottedkey(logdict,self.logconfig["json_delimiter"]):
                            yield (json.dumps(record, ensure_ascii=False), record, logmeta)
                    else:
                        yield (lograw, logdict, logmeta)
                elif logdict == 'regex_error':
                    self.error_logs_count += 1
        elif self.via_firelens:
            for lograw, logdict, logmeta in self.extract_firelens_log(
                    start, end, logmeta):
                if logmeta.get('is_ignored'):
                    yield (lograw, {}, logmeta)
                elif logmeta.get('__skip_normalization'):
                    yield (lograw, {}, logmeta)
                else:
                    yield (lograw, logdict, logmeta)
        else:
            # json, text, csv, multiline, xml, winevtxml, parquet
            yield from self.rawfile_instacne.extract_log(start, end, logmeta)

    def set_start_end_position(self, ignore_header_line_number=None):
        if not ignore_header_line_number:
            # if self.via_cwl:
            #    ignore_header_line_number = 0
            ignore_header_line_number = (
                self.rawfile_instacne.ignore_header_line_number)

        if self.start_number <= ignore_header_line_number:
            start = ignore_header_line_number + 1
            if self.max_log_count >= self.log_count:
                end = self.log_count
            else:
                end = self.max_log_count
        else:
            start = self.start_number
            end = self.end_number
        return start, end

    def extract_file_timestamp(self):
        re_file_timestamp_format = self.logconfig['file_timestamp_format']
        if re_file_timestamp_format:
            m = re_file_timestamp_format.search(self.s3key)
            if m:
                year = int(m.groupdict().get('year', 2000))
                month = int(m.groupdict().get('month', 1))
                day = int(m.groupdict().get('day', 1))
                hour = int(m.groupdict().get('hour', 0))
                minute = int(m.groupdict().get('minute', 0))
                second = int(m.groupdict().get('second', 0))
                microsecond = int(m.groupdict().get('microsecond', 0))
                dt = datetime(year, month, day, hour, minute, second,
                              microsecond, tzinfo=timezone.utc)
            else:
                msg = (f'invalid file timestamp format regex, '
                       f're_file_timestamp_format, for {self.s3key}')
                logger.critical(msg)
                raise Exception(msg) from None
            return dt
        else:
            return None

    def log_count_cwl_log(self):
        idx: int = 0
        line_num: int = 0
        decoder = json.JSONDecoder()
        body: str = self.__rawdata.read()
        body_size: int = len(body)
        _w = json.decoder.WHITESPACE.match

        while True:
            # skip leading whitespace
            idx = _w(body, idx).end()
            if idx >= body_size:
                break
            obj, idx = decoder.raw_decode(body, idx=idx)
            if (isinstance(obj, dict)
                    and 'logEvents' in obj
                    and obj['messageType'] == 'DATA_MESSAGE'):
                line_num += len(obj['logEvents'])

        return line_num

    def extract_cwl_log(self, start, end, logmeta={}):
        idx: int = 0
        line_num: int = 0
        decoder = json.JSONDecoder()
        self.__rawdata.seek(0)
        body: str = self.__rawdata.read()
        body_size: int = len(body)
        _w = json.decoder.WHITESPACE.match

        while True:
            # skip leading whitespace
            idx = _w(body, idx).end()
            if idx >= body_size:
                break
            obj, idx = decoder.raw_decode(body, idx=idx)
            if (isinstance(obj, dict)
                    and 'logEvents' in obj
                    and obj['messageType'] == 'DATA_MESSAGE'):
                cwl_logmeta = copy.copy(logmeta)
                cwl_logmeta['cwl_accountid'] = obj['owner']
                cwl_logmeta['loggroup'] = obj['logGroup']
                cwl_logmeta['logstream'] = obj['logStream']
                for logevent in obj['logEvents']:
                    line_num += 1
                    if start <= line_num <= end:
                        cwl_logmeta['cwl_id'] = logevent['id']
                        cwl_logmeta['cwl_timestamp'] = logevent['timestamp']
                        yield (logevent['message'], cwl_logmeta)

    def extract_firelens_log(self, start, end, logmeta={}):
        ignore_container_stderr_bool = (
            self.logconfig['ignore_container_stderr'])
        start_index = start - 1
        end_index = end
        for logdata in self.rawdata.readlines()[start_index:end_index]:
            obj = json.loads(logdata.strip())
            logdict = {}
            firelens_logmeta = copy.copy(logmeta)
            # basic firelens field
            firelens_logmeta['container_id'] = obj.get('container_id')
            firelens_logmeta['container_name'] = obj.get('container_name')
            firelens_logmeta['container_source'] = obj.get('source')
            firelens_logmeta['ecs_cluster'] = obj.get('ecs_cluster')
            firelens_logmeta['ecs_task_arn'] = obj.get('ecs_task_arn')
            firelens_logmeta['ecs_task_definition'] = obj.get(
                'ecs_task_definition')
            ec2_instance_id = obj.get('ec2_instance_id', False)
            if ec2_instance_id:
                firelens_logmeta['ec2_instance_id'] = ec2_instance_id
            # original log
            logdata = obj['log']
            # ignore stderr if necessary
            if firelens_logmeta['container_source'] == 'stderr':
                if ignore_container_stderr_bool:
                    reason = "log is container's stderr"
                    firelens_logmeta['is_ignored'] = True
                    firelens_logmeta['ignored_reason'] = reason
                    yield (logdata, logdict, firelens_logmeta)
                    continue

            try:
                logdict = (
                    self.rawfile_instacne.convert_lograw_to_dict(logdata))
                if (logdict == 'regex_error'
                        and firelens_logmeta['container_source'] == 'stderr'):
                    raise Exception('regex_error')
            except Exception as err:
                firelens_logmeta['__skip_normalization'] = True
                firelens_logmeta['__error_message'] = logdata
                if firelens_logmeta['container_source'] != 'stderr':
                    firelens_logmeta['__error_message'] = err
                    logger.warning(f'{err} {self.s3key}')
            yield (logdata, logdict, firelens_logmeta)

    def extract_rawdata_from_s3obj(self):
        try:
            obj = self.s3_client.get_object(
                Bucket=self.s3bucket, Key=self.s3key)
        except Exception as err:
            msg = f'Failed to download s3://{self.s3bucket}/{self.s3key}'
            logger.exception(msg)
            raise Exception(f'{msg}. {err}') from None
        try:
            s3size = int(
                obj['ResponseMetadata']['HTTPHeaders']['content-length'])
        except Exception:
            s3size = 20
        if s3size < 20:
            self.is_ignored = True
            self.ignored_reason = (f'no valid contents in s3 object, size of '
                                   f'{self.s3key} is only {s3size} byte')
            return None
        rawbody = io.BytesIO(obj['Body'].read())
        # confirmd and ignored Rule-884405
        mime_type = utils.get_mime_type(rawbody.read(16))
        rawbody.seek(0)
        if mime_type == 'text':
            body = io.TextIOWrapper(rawbody, encoding='utf8', errors='ignore')
        elif mime_type == 'parquet':
            body = rawbody
            # confirmd and ignored Rule-884405
            self.file_format = 'parquet'
        elif mime_type == 'gzip':
            body = gzip.open(rawbody, mode='rb')
        elif mime_type == 'zip':
            z = zipfile.ZipFile(rawbody)
            body = z.open(z.namelist()[0])
        elif mime_type == 'bzip2':
            body = bz2.open(rawbody, mode='rb')
        else:
            logger.error('unknown file format')
            raise Exception('unknown file format')

        if mime_type not in ('text', 'parquet'):
            mime_type2 = utils.get_mime_type(body.read(16))
            if mime_type2 == 'parquet':
                body.seek(0)
                self.file_format = 'parquet'
            elif mime_type2 == 'text':
                rawbody.seek(0)
                if mime_type == 'gzip':
                    body = gzip.open(rawbody, mode='rt', encoding='utf8',
                                     errors='ignore')
                elif mime_type == 'zip':
                    z = zipfile.ZipFile(rawbody)
                    body = z.open(z.namelist()[0])
                    body = io.TextIOWrapper(body, encoding='utf8',
                                            errors='ignore')
                elif mime_type == 'bzip2':
                    body = bz2.open(rawbody, mode='rt', encoding='utf8',
                                    errors='ignore')
            elif mime_type2 in ('gzip', 'zip', 'bzip2'):
                msg = f'double archived file. {mime_type2} in {mime_type}'
                logger.error(msg)
                raise Exception(msg)
        return body

    def split_logs(self, log_count, max_log_count):
        q, mod = divmod(log_count, max_log_count)
        if mod != 0:
            q = q + 1
        splite_logs_list = []
        for x in range(q):
            if x == 0:
                start = 1
            else:
                start = x * max_log_count + 1
            end = (x + 1) * max_log_count
            if (x == q - 1) and (mod != 0):
                end = x * max_log_count + mod
            splite_logs_list.append((start, end))
        return splite_logs_list

    def send_meta_to_sqs(self, metadata):
        logger.debug({'split_logs': f's3://{self.s3bucket}/{self.s3key}',
                      'max_log_count': self.max_log_count,
                      'log_count': self.log_count})
        entries = []
        last_num = len(metadata)
        for i, (start, end) in enumerate(metadata):
            queue_body = {
                "siem": {"start_number": start, "end_number": end},
                "s3": {"bucket": {"name": self.s3bucket},
                       "object": {"key": self.s3key}}}
            message_body = json.dumps(queue_body)
            entries.append({'Id': f'num_{start}', 'MessageBody': message_body})
            if (len(entries) == 10) or (i == last_num - 1):
                response = self.sqs_queue.send_messages(Entries=entries)
                if response['ResponseMetadata']['HTTPStatusCode'] != 200:
                    logger.error(json.dumps(response))
                    raise Exception(json.dumps(response))
                entries = []
        return last_num


class LogParser:
    """LogParser class.

    生ファイルから、ファイルタイプ毎に、タイムスタンプの抜き出し、
    テキストなら名前付き正規化による抽出、エンリッチ(geoipなどの付与)、
    フィールドのECSへの統一、最後にJSON化、する
    """
    def __init__(self, logfile, logconfig, sf_module, geodb_instance,
                 ioc_instance, xff_instance):
        self.logfile = logfile
        self.logconfig = logconfig
        self.sf_module = sf_module
        self.geodb_instance = geodb_instance
        self.ioc_instance = ioc_instance
        self.xff_instance = xff_instance

        self.logtype = logfile.logtype
        self.s3key = logfile.s3key
        self.s3bucket = logfile.s3bucket
        self.logformat = logfile.file_format
        self.accountid = logfile.accountid
        self.region = logfile.region
        self.loggroup = None
        self.logstream = None
        self.via_firelens = logfile.via_firelens

        self.timestamp_tz = timezone(
            timedelta(hours=float(self.logconfig['timestamp_tz'])))
        if self.logconfig['index_tz']:
            self.index_tz = timezone(
                timedelta(hours=float(self.logconfig['index_tz'])))
        self.has_nanotime = self.logconfig['timestamp_nano']

    def __call__(self, lograw, logdict, logmeta):
        if isinstance(logdict, dict):
            pass
        elif logdict == 'regex_error':
            self.__logdata_dict = {'is_ignored': True}
            self.logfile.error_logs_count += 1
            return

        self.__skip_normalization = False
        self.lograw = lograw
        self.__logdata_dict = logdict
        self.logmeta = logmeta
        self.original_fields = set(logdict.keys())
        self.additional_id = None
        if logmeta:
            self.additional_id = logmeta.get('cwl_id')
            self.additional_id = logmeta.get('cwe_id', self.additional_id)
            self.logstream = logmeta.get('logstream')
            self.loggroup = logmeta.get('loggroup')
            self.accountid = logmeta.get('cwl_accountid', self.accountid)
            self.accountid = logmeta.get('cwe_accountid', self.accountid)
            self.region = logmeta.get('cwe_region', self.region)
            self.cwl_id = logmeta.get('cwl_id')
            self.cwl_timestamp = logmeta.get('cwl_timestamp')
            self.cwe_id = logmeta.get('cwe_id')
            self.cwe_timestamp = logmeta.get('cwe_timestamp')
            self.file_timestamp = logmeta.get('file_timestamp')
        if logmeta.get('container_name'):
            self.additional_id = logmeta['container_name']
            # Firelens. for compatibility
            self.__logdata_dict = dict(self.__logdata_dict, **logmeta)
            if 'file_timestamp' in self.__logdata_dict:
                del self.__logdata_dict['file_timestamp']
        if self.is_ignored:
            return
        self.__event_ingested = datetime.now(timezone.utc)
        self.__skip_normalization = self.set_skip_normalization()

        self.rename_fields()
        self.__timestamp = self.get_timestamp()
        # idなどの共通的なフィールドを追加する
        self.add_basic_field()
        # logger.debug({'doc_id': self.doc_id})
        # 同じフィールド名で複数タイプがあるとESにロードするとエラーになるので
        # 該当フィールドだけテキスト化する
        self.clean_multi_type_field()
        # フィールドをECSにマッピングして正規化する
        self.transform_to_ecs()
        # 一部のフィールドを修正する
        self.transform_by_script()
        # ログにgeoipなどの情報をエンリッチ
        self.enrich()
        # add filed prefix to original log
        self.add_field_prefix()
        # exclude logs by conditional expressions in Parameter Store
        self.exclude_logs_by_conditions()

    ###########################################################################
    # Property
    ###########################################################################
    @property
    def is_ignored(self):
        if self.__logdata_dict.get('is_ignored'):
            self.ignored_reason = self.__logdata_dict.get('ignored_reason')
            return True
        elif 'exclusion_patterns' in self.logconfig:
            for pattern in self.logconfig['exclusion_patterns']:
                is_excluded, ex_pattern = (
                    utils.match_log_with_exclude_patterns(
                        self.__logdata_dict, pattern))
                if is_excluded:
                    self.ignored_reason = (
                        f'matched {ex_pattern} with log_exclusion_patterns')
                    return True
        return False

    @property
    def timestamp(self):
        return self.__timestamp

    @property
    def event_ingested(self):
        return self.__event_ingested

    @property
    def doc_id(self):
        if '__doc_id_suffix' in self.__logdata_dict:
            # this field is added by sf_ script
            temp = self.__logdata_dict['__doc_id_suffix']
            del self.__logdata_dict['__doc_id_suffix']
            return '{0}_{1}'.format(self.__logdata_dict['@id'], temp)
        if self.logconfig['doc_id_suffix']:
            suffix = utils.value_from_nesteddict_by_dottedkey(
                self.__logdata_dict, self.logconfig['doc_id_suffix'])
            if suffix:
                return '{0}_{1}'.format(self.__logdata_dict['@id'], suffix)
        return self.__logdata_dict['@id']

    @property
    def indexname(self):
        if '__index_name' in self.__logdata_dict:
            # this field is added by sf_ script
            indexname = self.__logdata_dict['__index_name']
            del self.__logdata_dict['__index_name']
        else:
            indexname = self.logconfig['index_name']

        if self.logconfig['index_rotation'] == 'aoss':
            if '__index_dt' in self.__logdata_dict:
                del self.__logdata_dict['__index_dt']
            if self.logconfig['index_suffix']:
                indexname = f"{indexname}-{self.logconfig['index_suffix']}"
            else:
                indexname = f'{indexname}-001'
            return indexname

        if 'auto' in self.logconfig['index_rotation']:
            return indexname
        if self.logconfig['index_suffix']:
            indexname = f"{indexname}-{self.logconfig['index_suffix']}"
        if 'event_ingested' in self.logconfig['index_time']:
            index_dt = self.event_ingested
        elif '__index_dt' in self.__logdata_dict:
            # this field is added by sf_ script
            index_dt = self.__logdata_dict['__index_dt']
            del self.__logdata_dict['__index_dt']
        else:
            index_dt = self.timestamp
        if self.logconfig['index_tz']:
            index_dt = index_dt.astimezone(self.index_tz)
        if 'daily' in self.logconfig['index_rotation']:
            return indexname + index_dt.strftime('-%Y-%m-%d')
        elif 'weekly' in self.logconfig['index_rotation']:
            return indexname + index_dt.strftime('-%Y-w%W')
        elif 'monthly' in self.logconfig['index_rotation']:
            return indexname + index_dt.strftime('-%Y-%m')
        else:
            return indexname + index_dt.strftime('-%Y')

    @property
    def json(self):
        # 内部で管理用のフィールドを削除
        self.__logdata_dict = self.del_none(self.__logdata_dict)
        loaded_data = json.dumps(self.__logdata_dict, cls=utils.MyEncoder)
        # サイズが Lucene の最大値である 32766 Byte を超えてるかチェック
        if len(loaded_data) >= 65536:
            self.__logdata_dict = self.truncate_big_field(self.__logdata_dict)
            loaded_data = json.dumps(self.__logdata_dict, cls=utils.MyEncoder)
        return loaded_data

    ###########################################################################
    # Method/Function - Main
    ###########################################################################
    def add_basic_field(self):
        basic_dict = {}
        basic_dict['@message'] = self.lograw
        basic_dict['@timestamp'] = self.timestamp.isoformat()
        basic_dict['@log_type'] = self.logtype
        basic_dict['@log_s3bucket'] = self.s3bucket
        basic_dict['@log_s3key'] = self.s3key
        basic_dict['@log_group'] = self.loggroup
        basic_dict['@log_stream'] = self.logstream
        basic_dict['event'] = {'module': self.logtype}
        basic_dict['event']['ingested'] = self.event_ingested.isoformat()
        if self.__skip_normalization:
            unique_text = (
                f'{basic_dict["@message"]}{self.s3key}{self.additional_id}')
            basic_dict['@id'] = hashlib.md5(
                unique_text.encode('utf-8')).hexdigest()
            # confirmd and ignored Rule-143469
            del unique_text
            if '__error_message' in self.__logdata_dict:
                self.__logdata_dict['error'] = {
                    'message': self.__logdata_dict['__error_message']}
                del self.__logdata_dict['__error_message']

        elif self.logconfig['doc_id']:
            basic_dict['@id'] = self.__logdata_dict[self.logconfig['doc_id']]
        elif self.additional_id:
            unique_text = f'{basic_dict["@message"]}{self.additional_id}'
            basic_dict['@id'] = hashlib.md5(
                unique_text.encode('utf-8')).hexdigest()
            del unique_text
        else:
            unique_text = f'{basic_dict["@message"]}'
            basic_dict['@id'] = hashlib.md5(
                unique_text.encode('utf-8')).hexdigest()
            del unique_text
        self.__logdata_dict = utils.merge_dicts(
            self.__logdata_dict, basic_dict)

    def rename_fields(self):
        if self.__skip_normalization:
            return False
        elif self.logconfig.get('renamed_newfields'):
            for field in self.logconfig['renamed_newfields']:
                v = self.__logdata_dict.get(self.logconfig[field])
                if v:
                    self.__logdata_dict[field] = v
                    del self.__logdata_dict[self.logconfig[field]]
                    # fix oroginal field name list
                    self.original_fields.add(field)
                    self.original_fields.remove(self.logconfig[field])

    def clean_multi_type_field(self):
        clean_multi_type_dict = {}
        multifield_keys = self.logconfig['json_to_text'].split()
        for multifield_key in multifield_keys:
            v = utils.value_from_nesteddict_by_dottedkey(
                self.__logdata_dict, multifield_key)
            if v:
                # json obj in json obj
                if isinstance(v, int):
                    new_dict = utils.put_value_into_nesteddict(
                        multifield_key, v)
                elif '{' in v:
                    new_dict = utils.put_value_into_nesteddict(
                        multifield_key, repr(v))
                else:
                    new_dict = utils.put_value_into_nesteddict(
                        multifield_key, str(v))
                clean_multi_type_dict = utils.merge_dicts(
                    clean_multi_type_dict, new_dict)
        self.__logdata_dict = utils.merge_dicts(
            self.__logdata_dict, clean_multi_type_dict)

    def get_value_and_input_into_ecs_dict(self, ecs_dict):
        new_ecs_dict = {}
        ecs_keys = self.logconfig['ecs']
        for ecs_key in ecs_keys:
            original_keys = self.logconfig[ecs_key]
            if isinstance(original_keys, str):
                v = utils.value_from_nesteddict_by_dottedkeylist(
                    self.__logdata_dict, original_keys)
                if isinstance(v, str):
                    v = utils.validate_ip(v, ecs_key)
                if v == 0 or v:
                    new_ecs_dict = utils.put_value_into_nesteddict(ecs_key, v)
            elif isinstance(original_keys, list):
                temp_list = []
                for original_key_list in original_keys:
                    v = utils.value_from_nesteddict_by_dottedkeylist(
                        self.__logdata_dict, original_key_list)
                    if isinstance(v, str):
                        v = utils.validate_ip(v, ecs_key)
                        if v:
                            temp_list.append(v)
                    elif isinstance(v, list):
                        for i in v:
                            each_v = utils.validate_ip(i, ecs_key)
                            if each_v:
                                temp_list.append(each_v)
                if temp_list:
                    new_ecs_dict = utils.put_value_into_nesteddict(
                        ecs_key, sorted(list(set(temp_list))))
            if new_ecs_dict:
                new_ecs_dict = utils.merge_dicts(ecs_dict, new_ecs_dict)
        return ecs_dict

    def transform_to_ecs(self):
        cloud = self.__logdata_dict.get('cloud', {})
        csp = cloud.get('provider')
        account1 = cloud.get('account', {}).get('id')
        region = cloud.get('region')

        ecs_dict = {'ecs': {'version': self.logconfig['ecs_version']}}
        if not csp and self.logconfig['cloud_provider']:
            ecs_dict['cloud'] = {'provider': self.logconfig['cloud_provider']}

        ecs_dict = self.get_value_and_input_into_ecs_dict(ecs_dict)
        is_cloud = 'cloud' in ecs_dict or 'cloud' in self.__logdata_dict
        if is_cloud:
            ecs_dict.setdefault('cloud', {})

        if not account1 and is_cloud:
            # Set AWS Account ID
            account2 = ecs_dict['cloud'].get('account', {}).get('id')
            if account2:
                if account2 == 'unknown':
                    # for vpcflowlogs
                    ecs_dict['cloud']['account'] = {'id': self.accountid}
            elif self.accountid:
                ecs_dict['cloud']['account'] = {'id': self.accountid}
            else:
                ecs_dict['cloud']['account'] = {'id': 'unknown'}

        if not region and is_cloud:
            # Set AWS Region
            if 'region' in ecs_dict['cloud']:
                pass
            elif self.region:
                ecs_dict['cloud']['region'] = self.region
            else:
                ecs_dict['cloud']['region'] = 'unknown'

        # get info from firelens metadata of Elastic Container Serivce
        if 'ecs_task_arn' in self.logmeta:
            ecs_task_arn_taple = self.logmeta['ecs_task_arn'].split(':')
            ecs_dict['cloud']['account']['id'] = ecs_task_arn_taple[4]
            ecs_dict['cloud']['region'] = ecs_task_arn_taple[3]
            if 'ec2_instance_id' in self.logmeta:
                ecs_dict['cloud']['instance'] = {
                    'id': self.logmeta['ec2_instance_id']}
            ecs_dict['container'] = {
                'id': self.logmeta['container_id'],
                'name': self.logmeta['container_name']}

        if '__error_message' in self.logmeta:
            self.__logdata_dict['error'] = {
                'message': self.logmeta['__error_message']}
            del self.logmeta['__error_message']

        static_ecs_keys = self.logconfig['static_ecs']
        for static_ecs_key in static_ecs_keys:
            v = copy.copy(self.logconfig[static_ecs_key])
            new_ecs_dict = utils.put_value_into_nesteddict(static_ecs_key, v)
            ecs_dict = utils.merge_dicts(ecs_dict, new_ecs_dict)
        self.__logdata_dict = utils.merge_dicts(self.__logdata_dict, ecs_dict)

    def transform_by_script(self):
        if self.logconfig['script_ecs']:
            try:
                self.__logdata_dict = self.sf_module.transform(
                    self.__logdata_dict)
            except Exception:
                # self.logfile.error_logs_count += 1
                logger.exception(
                    f'Exception error has occurs in sf_{self.logtype}.py')

    def create_ioc_ip_dict(self, ioc_ip_dict, ip, field):
        if ip not in ioc_ip_dict:
            ioc_ip_dict[ip] = [field]
        else:
            ioc_ip_dict[ip].append(field)
        return ioc_ip_dict

    def create_ioc_domain_dict(self, ioc_domain_dict, domain, field):
        if domain not in ioc_domain_dict:
            ioc_domain_dict[domain] = [field]
        else:
            ioc_domain_dict[domain].append(field)
        return ioc_domain_dict

    def enrich(self):
        enrich_dict = {}

        # select client ip from X-Forwarded-For
        clientip_xff = self.logconfig['clientip_xff']
        if len(clientip_xff) == 2 and self.xff_instance.is_enabled:
            key_clientip = clientip_xff[0]
            key_xff = clientip_xff[1]

            xff = utils.value_from_nesteddict_by_dottedkey(
                self.__logdata_dict, key_xff)
            if xff and len(xff) > 0:
                sourceip = utils.value_from_nesteddict_by_dottedkey(
                    self.__logdata_dict, key_clientip)
                clientip = self.xff_instance.select_clientip_from_xff(
                    sourceip, xff)
                if clientip and (sourceip != clientip):
                    temp_dict = utils.put_value_into_nesteddict(
                        key_clientip, clientip)
                    self.__logdata_dict = utils.merge_dicts(
                        self.__logdata_dict, temp_dict)

        # geoip
        geoip_list = self.logconfig['geoip'].split()
        for geoip_ecs in geoip_list:
            try:
                ipaddr = self.__logdata_dict[geoip_ecs]['ip']
            except KeyError:
                continue
            geoip, asn = self.geodb_instance.check_ipaddress(ipaddr)
            if geoip:
                enrich_dict[geoip_ecs] = {'geo': geoip}
            if geoip and asn:
                enrich_dict[geoip_ecs].update({'as': asn})
            elif asn:
                enrich_dict[geoip_ecs] = {'as': asn}

        # IOC
        enrich_dict['threat.enrichments'] = []

        ioc_ip_list = self.logconfig['ioc_ip']
        if ioc_ip_list and self.ioc_instance.is_enabled:
            ioc_ip_dict = {}
            for field in ioc_ip_list:
                ips = utils.value_from_nesteddict_by_dottedkey(
                    self.__logdata_dict, field)
                if isinstance(ips, str):
                    ioc_ip_dict = self.create_ioc_ip_dict(
                        ioc_ip_dict, ips, field)
                elif isinstance(ips, list):
                    for ip in ips:
                        ioc_ip_dict = self.create_ioc_ip_dict(
                            ioc_ip_dict, ip, field)
            for ipaddr, fields in ioc_ip_dict.items():
                enrichments = self.ioc_instance.check_ipaddress(ipaddr)
                if enrichments:
                    enrichments = self.ioc_instance.add_mached_fields(
                        enrichments, fields)
                    enrich_dict['threat.enrichments'].extend(enrichments)

        ioc_domain_list = self.logconfig['ioc_domain']
        if ioc_domain_list and self.ioc_instance.is_enabled:
            ioc_domain_dict = {}
            for field in ioc_domain_list:
                domains = utils.value_from_nesteddict_by_dottedkey(
                    self.__logdata_dict, field)
                if isinstance(domains, str):
                    ioc_domain_dict = self.create_ioc_domain_dict(
                        ioc_domain_dict, domains, field)
                elif isinstance(domains, list):
                    for domain in domains:
                        ioc_domain_dict = self.create_ioc_domain_dict(
                            ioc_domain_dict, domain, field)
            for domain, fields in ioc_domain_dict.items():
                enrichments = self.ioc_instance.check_domain(domain)
                if enrichments:
                    enrichments = self.ioc_instance.add_mached_fields(
                        enrichments, fields)
                    enrich_dict['threat.enrichments'].extend(enrichments)
        if len(enrich_dict['threat.enrichments']) == 0:
            del enrich_dict['threat.enrichments']
        else:
            providers = set()
            indicators = set()
            ioc_types = set()
            names = set()
            for item in enrich_dict['threat.enrichments']:
                providers.add(item['indicator']['provider'])
                ioc_types.add(item['indicator']['type'])
                indicators.add(item['indicator'].get('ip'))
                indicators.add(item['matched'].get('atomic'))
                names.add(item['indicator'].get('name'))
            indicators = [x for x in indicators if x is not None]
            names = [x for x in names if x is not None]
            enrich_dict['threat.matched'] = {
                'providers': list(providers), 'types': list(ioc_types),
                'indicators': indicators, 'names': names
            }

        # user-agent
        ua_field = self.logconfig['user_agent_enrichment_field']
        if ua_field:
            ua_value = self.__logdata_dict.get(ua_field)
            if ua_value:
                try:
                    original = self.__logdata_dict[ua_field]['original']
                except KeyError:
                    original = None
                if isinstance(original, list):
                    original = original[0]
                if isinstance(original, str) and original != '-':
                    enrich_dict[ua_field] = user_agent.enrich(original)

        # merge all enrichment
        self.__logdata_dict = utils.merge_dicts(
            self.__logdata_dict, enrich_dict)

    def add_field_prefix(self):
        if self.logconfig.get('field_prefix'):
            field_prefix = self.logconfig.get('field_prefix')
            if (field_prefix in self.__logdata_dict
                    and isinstance(self.__logdata_dict[field_prefix], dict)):
                pass
            else:
                self.__logdata_dict[field_prefix] = {}
            for field in self.original_fields:
                try:
                    self.__logdata_dict[field_prefix][field] = (
                        self.__logdata_dict[field])
                    del self.__logdata_dict[field]
                except KeyError:
                    pass

    def exclude_logs_by_conditions(self):
        if 'exclusion_conditions' not in self.logconfig:
            return
        record = self.__logdata_dict
        exclusion_conditions = self.logconfig['exclusion_conditions']
        is_matched_count_action = False
        for condition in exclusion_conditions:
            action = condition['action'].lower()
            expression = condition['expression']
            compiled_expression = condition['compiled_expression']
            condition_name = condition['name']
            try:
                is_excluded = compiled_expression.search(record)
            except Exception:
                msg = f"Failed to query JMESPath with '{condition_name}'"
                logger.exception(msg)
                continue
            if is_excluded:
                if action == 'exclude':
                    self.__logdata_dict['is_ignored'] = True
                    break
                if action == 'count':
                    is_matched_count_action = True
                    if self.logfile.counted_log_count > 2:
                        continue
                    logger.append_keys(
                        log_record=record,
                        condition_name=condition_name,
                        expression=expression)
                    logger.info(
                        f"Log record matched '{expression}' "
                        f"with {condition_name} in Parameter Store"
                    )
                    logger.remove_keys(
                        ["condition_name", "expression", "log_record"])
        if is_matched_count_action:
            self.logfile.counted_log_count += 1

    ###########################################################################
    # Method/Function - Support
    ###########################################################################
    def set_skip_normalization(self):
        if self.__logdata_dict.get('__skip_normalization'):
            del self.__logdata_dict['__skip_normalization']
            return True
        return False

    def get_timestamp(self):
        if ((self.logconfig['timestamp_key']
                or self.logconfig['timestamp_key_list'])
                and not self.__skip_normalization):

            timestamp_key_list = self.logconfig['timestamp_key_list']
            if timestamp_key_list:
                timestamp_key_list = timestamp_key_list.split()
            else:
                timestamp_key_list = [self.logconfig['timestamp_key'], ]

            timestamp_format_list = self.logconfig['timestamp_format_list']
            if not timestamp_format_list:
                timestamp_format_list = [self.logconfig['timestamp_format']]

            for timestamp_key in timestamp_key_list:
                if timestamp_key == 'cwe_timestamp':
                    self.__logdata_dict['cwe_timestamp'] = self.cwe_timestamp
                elif timestamp_key == 'cwl_timestamp':
                    self.__logdata_dict['cwl_timestamp'] = self.cwl_timestamp
                elif timestamp_key == 'file_timestamp':
                    return self.file_timestamp
                timestr = utils.get_timestr_from_logdata_dict(
                    self.__logdata_dict, timestamp_key, self.has_nanotime)
                if timestr is not None and timestr != '':
                    break

            if timestr is None or timestr == '':
                msg = f'there is no valid timestamp_key for {self.logtype}'
                logger.error(msg)
                raise ValueError(msg)
            dt = utils.convert_timestr_to_datetime_wrapper(
                timestr, timestamp_key, timestamp_format_list,
                self.timestamp_tz)
            if dt is None or dt == '':
                msg = f'there is no timestamp format for {self.logtype}'
                logger.error(msg)
                raise ValueError(msg)
        elif '@timestamp' in self.__logdata_dict:
            timestr = utils.get_timestr_from_logdata_dict(
                self.__logdata_dict, '@timestamp', self.has_nanotime)
            dt = utils.convert_timestr_to_datetime(
                timestr, '@timestamp', self.logconfig['timestamp_format'],
                self.timestamp_tz)
        else:
            if hasattr(self, 'file_timestamp') and self.file_timestamp:
                # This may be firelens and error log
                return self.file_timestamp
            elif hasattr(self, 'cwl_timestamp') and self.cwl_timestamp:
                # This may be CWL and truncated JSON such as opensearch audit
                return utils.convert_epoch_to_datetime(
                    self.cwl_timestamp, utils.TIMEZONE_UTC)
            # impossible to find any timestamp.
            # Set the current time as @timestamp
            dt = datetime.now(timezone.utc)
        if not dt:
            msg = f'there is no valid timestamp for {self.logtype}'
            logger.error(msg)
            raise ValueError(msg)
        return dt

    def del_none(self, d):
        """値のないキーを削除する。削除しないとESへのLoad時にエラーとなる """
        for key, value in list(d.items()):
            if isinstance(value, list):
                for v in value:
                    if isinstance(v, dict):
                        self.del_none(v)
            if isinstance(value, dict):
                self.del_none(value)
            if isinstance(value, dict) and len(value) == 0:
                del d[key]
            elif (isinstance(value, list)
                    and (len(value) == 0 or value == [''])):
                del d[key]
            elif isinstance(value, str) and (value in ('', '-', 'null', '[]')):
                del d[key]
            elif isinstance(value, type(None)):
                del d[key]
        return d

    def truncate_txt(self, txt, num):
        try:
            return txt.encode('utf-8')[:num].decode()
        except UnicodeDecodeError:
            return self.truncate_txt(txt, num - 1)

    def truncate_big_field(self, d):
        """ truncate big field if size is bigger than 32,766 byte

        field size が Lucene の最大値である 32766 Byte を超えてるかチェック
        超えてれば切り捨て。このサイズは lucene の制限値
        """
        for key, value in list(d.items()):
            if isinstance(value, dict):
                self.truncate_big_field(value)
            elif (isinstance(value, str) and (len(value) >= 16383)
                    and len(value.encode('utf-8', 'surrogatepass')) >= 32766):
                if key not in ("@message", ):
                    d[key] = self.truncate_txt(d[key], 32753) + '<<TRUNCATED>>'
                    logger.warning(
                        f'Data was truncated because the size of {key} field '
                        f'is bigger than 32,766. _id is {self.doc_id}')
        return d


###############################################################################
# DEPRECATED function. Moved to siem.utils
###############################################################################
def get_value_from_dict(dct, xkeys_list):
    """Deprecated. moved to utils.value_from_nesteddict_by_dottedkeylist.

    入れ子になった辞書に対して、dotを含んだkeyで値を
    抽出する。keyはリスト形式で複数含んでいたら分割する。
    値がなければ返値なし

    >>> dct = {'a': {'b': {'c': 123}}}
    >>> xkey = 'a.b.c'
    >>> get_value_from_dict(dct, xkey)
    123
    >>> xkey = 'x.y.z'
    >>> get_value_from_dict(dct, xkey)

    >>> xkeys_list = 'a.b.c x.y.z'
    >>> get_value_from_dict(dct, xkeys_list)
    123
    >>> dct = {'a': {'b': [{'c': 123}, {'c': 456}]}}
    >>> xkeys_list = 'a.b.0.c'
    >>> get_value_from_dict(dct, xkeys_list)
    123
    """
    for xkeys in xkeys_list.split():
        v = dct
        for k in xkeys.split('.'):
            try:
                k = int(k)
            except ValueError:
                pass
            try:
                v = v[k]
            except (TypeError, KeyError, IndexError):
                v = ''
                break
        if v:
            return v


def put_value_into_dict(key_str, v):
    """Deprecated.

    moved to utils.put_value_into_nesteddict
    dictのkeyにドットが含まれている場合に入れ子になったdictを作成し、値としてvを入れる.
    返値はdictタイプ。vが辞書ならさらに入れ子として代入。
    値がlistなら、カンマ区切りのCSVにした文字列に変換
    TODO: 値に"が入ってると例外になる。対処方法が見つからず返値なDROPPEDにしてるので改善する。#34

    >>> put_value_into_dict('a.b.c', 123)
    {'a': {'b': {'c': '123'}}}
    >>> put_value_into_dict('a.b.c', [123])
    {'a': {'b': {'c': '123'}}}
    >>> put_value_into_dict('a.b.c', [123, 456])
    {'a': {'b': {'c': '123,456'}}}
    >>> v = {'x': 1, 'y': 2}
    >>> put_value_into_dict('a.b.c', v)
    {'a': {'b': {'c': {'x': 1, 'y': 2}}}}
    >>> v = str({'x': "1", 'y': '2"3'})
    >>> put_value_into_dict('a.b.c', v)
    {'a': {'b': {'c': 'DROPPED'}}}
    """
    v = v
    xkeys = key_str.split('.')
    if isinstance(v, dict):
        json_data = r'{{"{0}": {1} }}'.format(xkeys[-1], json.dumps(v))
    elif isinstance(v, list):
        json_data = r'{{"{0}": "{1}" }}'.format(
            xkeys[-1], ",".join(map(str, v)))
    else:
        json_data = r'{{"{0}": "{1}" }}'.format(xkeys[-1], v)
    if len(xkeys) >= 2:
        xkeys.pop()
        for xkey in reversed(xkeys):
            json_data = r'{{"{0}": {1} }}'.format(xkey, json_data)
    try:
        new_dict = json.loads(json_data, strict=False)
    except json.decoder.JSONDecodeError:
        new_dict = put_value_into_dict(key_str, 'DROPPED')
    return new_dict


def conv_key(obj):
    """Deprecated.

    moved to utils.convert_key_to_safe_field
    dictのkeyに-が入ってたら_に置換する
    """
    if isinstance(obj, dict):
        for org_key in list(obj.keys()):
            new_key = org_key
            if '-' in org_key:
                new_key = org_key.translate({ord('-'): ord('_')})
                obj[new_key] = obj.pop(org_key)
            utils.conv_key(obj[new_key])
    elif isinstance(obj, list):
        for val in obj:
            utils.conv_key(val)
    else:
        pass


def merge(a, b, path=None):
    """Deprecated.

    merges b into a
    Moved to siem.utils.merge_dicts.
    """
    if path is None:
        path = []
    for key in b:
        if key in a:
            if isinstance(a[key], dict) and isinstance(b[key], dict):
                merge(a[key], b[key], path + [str(key)])
            elif a[key] == b[key]:
                pass  # same leaf value
            elif str(a[key]) in str(b[key]):
                # strで上書き。JSONだったのをstrに変換したデータ
                a[key] = b[key]
            else:
                # conflict and override original value with new one
                a[key] = b[key]
        else:
            a[key] = b[key]
    return a


def match_log_with_exclude_patterns(log_dict, log_patterns):
    """Deprecated.

    ログと、log_patterns を比較させる
    一つでもマッチングされれば、OpenSearch ServiceにLoadしない

    >>> pattern1 = 111
    >>> RE_BINGO = re.compile('^'+str(pattern1)+'$')
    >>> pattern2 = 222
    >>> RE_MISS = re.compile('^'+str(pattern2)+'$')
    >>> log_patterns = { \
    'a': RE_BINGO, 'b': RE_MISS, 'x': {'y': {'z': RE_BINGO}}}
    >>> log_dict = {'a': 111}
    >>> match_log_with_exclude_patterns(log_dict, log_patterns)
    True
    >>> log_dict = {'a': 21112}
    >>> match_log_with_exclude_patterns(log_dict, log_patterns)

    >>> log_dict = {'a': '111'}
    >>> match_log_with_exclude_patterns(log_dict, log_patterns)
    True
    >>> log_dict = {'aa': 222, 'a': 111}
    >>> match_log_with_exclude_patterns(log_dict, log_patterns)
    True
    >>> log_dict = {'x': {'y': {'z': 111}}}
    >>> match_log_with_exclude_patterns(log_dict, log_patterns)
    True
    >>> log_dict = {'x': {'y': {'z': 222}}}
    >>> match_log_with_exclude_patterns(log_dict, log_patterns)

    >>> log_dict = {'x': {'hoge':222, 'y': {'z': 111}}}
    >>> match_log_with_exclude_patterns(log_dict, log_patterns)
    True
    >>> log_dict = {'a': 222}
    >>> match_log_with_exclude_patterns(log_dict, log_patterns)

    """
    for key, pattern in log_patterns.items():
        if key in log_dict:
            if isinstance(pattern, dict) and isinstance(log_dict[key], dict):
                res = match_log_with_exclude_patterns(log_dict[key], pattern)
                return res
            elif isinstance(pattern, re.Pattern):
                if isinstance(log_dict[key], list):
                    pass
                elif pattern.match(str(log_dict[key])):
                    return True

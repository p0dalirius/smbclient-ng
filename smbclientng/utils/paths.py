#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : paths.py
# Author             : Podalirius (@podalirius_)
# Date created       : 21 mar 2025

import ntpath


def normalize_alternate_data_stream_path(path: str) -> str:
    """
    Normalizes the path by removing the stream name if present.
    """

    basename = ntpath.basename(path)
    dirname = ntpath.dirname(path)

    if is_alternate_data_stream_path(path):
        elements = basename.split(':',2)
        if len(elements) == 2:
            basename, stream_name = elements[0], elements[1]
            stream_type = '$DATA'
        else:
            basename, stream_name, stream_type = elements[0], elements[1], elements[2]
            if len(stream_type) == 0:
                stream_type = '$DATA'

        path = ntpath.normpath(dirname + ntpath.sep + basename + ':' + stream_name + ':' + stream_type)
    else:
        path = ntpath.normpath(dirname + ntpath.sep + basename)

    return path

def is_alternate_data_stream_path(path: str) -> bool:
    """
    Checks if the path is an alternate data stream path.
    """
    basename = ntpath.basename(path)
    return ':' in basename
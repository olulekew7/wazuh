# coding: utf-8

from __future__ import absolute_import

from datetime import date, datetime  # noqa: F401
from typing import List, Dict  # noqa: F401

from api.models.base_model_ import Body


class GroupAddedModel(Body):

    def __init__(self, group_name: str = None):
        """GroupAddedModel body model.

        Parameters
        ----------
        group_name : str
            Group name.
        """
        self.swagger_types = {
            'group_name': str,
        }

        self.attribute_map = {
            'group_name': 'group_name',
        }

        self._group_name = group_name

    @property
    def group_name(self) -> str:
        """Group name getter.
        Returns
        -------
        group_name : str
            Group name.
        """
        return self._group_name

    @group_name.setter
    def group_name(self, group_name):
        """Group name setter.
        Parameters
        ----------
        group_name : str
            Group name.
        """
        self._group_name = group_name

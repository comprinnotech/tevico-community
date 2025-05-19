
from abc import ABC, abstractclassmethod, abstractmethod


class Channel(ABC):
    
    @abstractmethod
    def send_notification():
        raise NotImplementedError()
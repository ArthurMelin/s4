from collections.abc import Callable
from ctypes import c_void_p


class smart_ptr[T: c_void_p]:
    def __init__(self, value: T | None, deleter: Callable[[T], None]):
        self.__value = value
        self.__deleter = deleter

    def __bool__(self):
        return bool(self.__value)

    def __del__(self):
        if self.__value:
            self.__deleter(self.__value)

    @property
    def value(self) -> T:
        if self.__value is None:
            raise RuntimeError("null ptr dereference")
        return self.__value

    def reset(self, value: T | None) -> None:
        if self.__value:
            self.__deleter(self.__value)
        self.__value = value

    def release(self) -> T | None:
        value, self.__value = self.__value, None
        return value

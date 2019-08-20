class Packet:
    def __init__(self, is_src, speed, count):
        self.is_src = is_src
        self.pos = 0 if is_src else count-1
        self.speed = speed if is_src else -speed
        self.count = count

    def move(self):
        self.pos += self.speed
        return self.pos < 0 or self.pos >= self.count

    def getPos(self):
        return self.pos

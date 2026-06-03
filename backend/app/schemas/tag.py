from pydantic import BaseModel


class TagCreate(BaseModel):
    name: str
    color: str = "#4fd1c5"


class TagRead(BaseModel):
    id: str
    case_id: str
    name: str
    color: str

    model_config = {"from_attributes": True}

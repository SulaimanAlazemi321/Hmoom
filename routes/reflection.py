from models import Reflection, Question
from database import localSession
from fastapi import  Depends, HTTPException, status, APIRouter
from typing import Annotated, Optional
from sqlalchemy.orm import Session
from pydantic import BaseModel, Field
from .user import get_current_user

router = APIRouter(
    tags=["Reflection"],
    prefix="/reflection"
)

# ---------Pydantic classes ------------- 

class Reflection_ID_Schema(BaseModel):
    id: int = Field(gt=0)

    model_config={"json_schema_extra": {
        "example": {
            "id": "TheID"
        }
    }}

class Reflection_Reflection_Schema(BaseModel):
    reflection: str = Field(min_length=2)
    date: Optional[str] = None 
    title: str = Field(min_length=2)
 

    model_config={"json_schema_extra": {
        "example": {
            "reflection": "Reflection...",
            "date": "December 25, 2023 at 3:45 PM",
            "title": "yourTitle",
            "user_id": "TheID"
        }
    }}

class Reflection_Reflection_ID_Schema(BaseModel):
    reflection: str = Field(min_length=2)
    id: int = Field(gt=0)
    model_config={"json_schema_extra": {
        "example": {
            "reflection": "Reflection...",
            "id": "TheID"
        }
    }}


class Question_Question_ID_Schema(BaseModel):
    question: str = Field(min_length=2)
    id: int = Field(gt=0)
    model_config={"json_schema_extra": {
        "example": {
            "question": "Question...",
            "id": "TheID"
        }
    }}


class Question_ID_Schema(BaseModel):
    id: int = Field(gt=0)
    model_config={"json_schema_extra": {
        "example": {
            "id": "TheID"
        }
    }}


class Question_Question_Schema(BaseModel):
    question: str = Field(min_length=2)
    model_config={"json_schema_extra": {
        "example": {
            "question": "question..."
        }
    }}


class Reflection_Reflection_ID_Schema(BaseModel):
    reflection: str = Field(min_length=2)
    title: Optional[str] = None
    id: int = Field(gt=0)
    model_config={"json_schema_extra": {
        "example": {
            "reflection": "Reflection...",
            "title": "Updated title",
            "id": "TheID"
        }
    }}


# ---------Get Local Session ------------- 

def get_db():
    db = localSession()
    try:
        yield db
    finally:
        db.close()

dbDepends = Annotated[Session, Depends(get_db)] 
userDepends = Annotated[dict, Depends(get_current_user)]


# ---------Get All Reflection ------------- 

@router.get("/get-reflections",  status_code=status.HTTP_200_OK)
async def get_reflections(db: dbDepends):
    return db.query(Reflection).all()


# ---------Get Reflection By ID ------------- 

@router.post("/get-reflection-by-id", status_code=status.HTTP_200_OK)
async def get_reflection_by_id(db: dbDepends, reflection_id: Reflection_ID_Schema):
    reflection = db.query(Reflection).filter(Reflection.id == reflection_id.id).first()

    if not reflection:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND) 

    return reflection


# ---------Add Reflection ------------- 
@router.post("/add-reflection", status_code=status.HTTP_201_CREATED)
async def add_reflection(db: dbDepends, reflection_ref: Reflection_Reflection_Schema, user: userDepends):
    if user is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="could not validate user")

    new_reflection = Reflection(
        reflection = reflection_ref.reflection,
        date = reflection_ref.date or "No date", 
        title = reflection_ref.title,
        user_id = user.get("id")
    )
    try:
        db.add(new_reflection)
        db.commit()
        db.refresh(new_reflection)
        return {
            "success": "Reflection Added", 
            "id": new_reflection.id,
            "title": new_reflection.title, 
            "date": new_reflection.date, 
            "reflection": new_reflection.reflection
        }
    except:
        db.rollback()
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR)
    
# ---------Update Reflection -------------

@router.put("/update-reflection-by-id", status_code=status.HTTP_204_NO_CONTENT)
async def update_reflection_by_id(db: dbDepends, reflection_parm: Reflection_Reflection_ID_Schema, user: userDepends):
    updated_Reflection = db.query(Reflection).filter(Reflection.id == reflection_parm.id).first()
    if not updated_Reflection:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND)
    
    updated_Reflection.reflection = reflection_parm.reflection
    if reflection_parm.title:  # Update title if provided
        updated_Reflection.title = reflection_parm.title
    updated_Reflection.user_id = user.get("id")
    try: 
        db.add(updated_Reflection)
        db.commit()
        return {"Success": "Reflection Updated"}

    except:
        db.rollback()
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR)

# ---------Delete Reflection -------------

@router.delete("/delete-reflection-by-id", status_code=status.HTTP_204_NO_CONTENT)
async def delete_reflection_by_id(db: dbDepends, reflection_parm: Reflection_ID_Schema):
    deleted_reflection = db.query(Reflection).filter(Reflection.id == reflection_parm.id).first()
    if not deleted_reflection:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND)
    
    try:
        db.delete(deleted_reflection)
        db.commit()
        return {"Seccuss": "Reflection Deleted"}
    except:
        db.rollback()
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR)



# ---------Get All Questions ------------- 

@router.get("/get-questions",  status_code=status.HTTP_200_OK)
async def get_reflections(db: dbDepends):
    return db.query(Question).all()





# ---------Add Question -------------

@router.post("/add-question", status_code=status.HTTP_201_CREATED)
async def add_reflection_by_id(db: dbDepends, question_parm: Question_Question_Schema):
   
    
    new_question = Question(
        question = question_parm.question
    )
    try: 
        db.add(new_question)
        db.commit()
        return {"Seccuss": "Question Added"}
    except:
        db.rollback()
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR)




# ---------Delete Question -------------
@router.delete("/delete-question-by-id", status_code=status.HTTP_204_NO_CONTENT)
async def delete_reflection_by_id(db: dbDepends, question_parm: Question_ID_Schema):
    deleted_question = db.query(Question).filter(Question.id == question_parm.id).first()
    if not deleted_question:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND)
    
    try:
        db.delete(deleted_question)
        db.commit()
        return {"Seccuss": "Question Deleted"}
    except:
        db.rollback()
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR)

# ---------Update Question -------------
@router.put("/update-question-by-id", status_code=status.HTTP_204_NO_CONTENT)
async def update_question_by_id(db: dbDepends, question_parm: Question_Question_ID_Schema):
    updated_question = db.query(Question).filter(Question.id == question_parm.id).first()
    if not updated_question:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND)
    
    updated_question.question = question_parm.question
    try: 
        db.add(updated_question)
        db.commit()
        return {"Seccuss": "Question Updated"}

    except:
        db.rollback()
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR)
    

"""
Reflection and Question management routes.

This module handles CRUD operations for user reflections and admin question management.
"""
from typing import Annotated, Optional

from fastapi import Depends, HTTPException, status, APIRouter
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from models import Reflection, Question
from database import localSession
from .user import get_current_user

router = APIRouter(
    tags=["Reflection"],
    prefix="/reflection"
)


# ========== Pydantic Schemas ==========

class ReflectionIdSchema(BaseModel):
    """Schema for operations requiring only reflection ID."""
    id: int = Field(gt=0, description="Reflection ID")
    
    model_config = {
        "json_schema_extra": {
            "example": {"id": 1}
        }
    }


class ReflectionCreateSchema(BaseModel):
    """Schema for creating a new reflection."""
    title: str = Field(min_length=2, max_length=200, description="Reflection title")
    reflection: str = Field(min_length=2, description="Reflection content")
    date: Optional[str] = Field(None, description="Reflection date")
    
    model_config = {
        "json_schema_extra": {
            "example": {
                "title": "My Daily Reflection",
                "reflection": "Today I learned...",
                "date": "December 25, 2023 at 3:45 PM"
            }
        }
    }


class ReflectionUpdateSchema(BaseModel):
    """Schema for updating a reflection."""
    id: int = Field(gt=0, description="Reflection ID")
    reflection: str = Field(min_length=2, description="Updated reflection content")
    title: Optional[str] = Field(None, min_length=2, max_length=200, description="Updated title")
    
    model_config = {
        "json_schema_extra": {
            "example": {
                "id": 1,
                "reflection": "Updated reflection content...",
                "title": "Updated title"
            }
        }
    }


class QuestionIdSchema(BaseModel):
    """Schema for operations requiring only question ID."""
    id: int = Field(gt=0, description="Question ID")
    
    model_config = {
        "json_schema_extra": {
            "example": {"id": 1}
        }
    }


class QuestionCreateSchema(BaseModel):
    """Schema for creating a new question."""
    question: str = Field(min_length=2, max_length=500, description="Question text")
    
    model_config = {
        "json_schema_extra": {
            "example": {"question": "What made you smile today?"}
        }
    }


class QuestionUpdateSchema(BaseModel):
    """Schema for updating a question."""
    id: int = Field(gt=0, description="Question ID")
    question: str = Field(min_length=2, max_length=500, description="Updated question text")
    
    model_config = {
        "json_schema_extra": {
            "example": {
                "id": 1,
                "question": "What are you grateful for today?"
            }
        }
    }


# ========== Database Dependencies ==========

def get_db():
    """Provide database session for dependency injection."""
    db = localSession()
    try:
        yield db
    finally:
        db.close()


DbSession = Annotated[Session, Depends(get_db)]
CurrentUser = Annotated[dict, Depends(get_current_user)]


# ========== Reflection Routes ==========

@router.get("/get-reflections", status_code=status.HTTP_200_OK)
async def get_all_reflections(db: DbSession, user: CurrentUser):
    """
    Get all reflections for the current user.
    
    Returns:
        List of user's reflections ordered by date.
    """
    return db.query(Reflection).filter(
        Reflection.user_id == user.get("id")
    ).order_by(Reflection.date.desc()).all()


@router.post("/get-reflection-by-id", status_code=status.HTTP_200_OK)
async def get_reflection_by_id(
    reflection_id: ReflectionIdSchema,
    db: DbSession,
    user: CurrentUser
):
    """
    Get a specific reflection by ID.
    
    Args:
        reflection_id: The ID of the reflection to retrieve.
        
    Returns:
        The requested reflection if found and belongs to user.
        
    Raises:
        HTTPException: If reflection not found or doesn't belong to user.
    """
    reflection = db.query(Reflection).filter(
        Reflection.id == reflection_id.id,
        Reflection.user_id == user.get("id")
    ).first()
    
    if not reflection:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Reflection not found"
        )
    
    return reflection


@router.post("/add-reflection", status_code=status.HTTP_201_CREATED)
async def add_reflection(
    reflection_data: ReflectionCreateSchema,
    db: DbSession,
    user: CurrentUser
):
    """
    Create a new reflection for the current user.
    
    Args:
        reflection_data: The reflection content and metadata.
        
    Returns:
        Success message with created reflection details.
    """
    new_reflection = Reflection(
        title=reflection_data.title,
        reflection=reflection_data.reflection,
        date=reflection_data.date or "No date",
        user_id=user.get("id")
    )
    
    try:
        db.add(new_reflection)
        db.commit()
        db.refresh(new_reflection)
        
        return {
            "success": "Reflection added successfully",
            "id": new_reflection.id,
            "title": new_reflection.title,
            "date": new_reflection.date,
            "reflection": new_reflection.reflection
        }
    except Exception as e:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to create reflection"
        )


@router.put("/update-reflection-by-id", status_code=status.HTTP_200_OK)
async def update_reflection(
    update_data: ReflectionUpdateSchema,
    db: DbSession,
    user: CurrentUser
):
    """
    Update an existing reflection.
    
    Args:
        update_data: The reflection ID and updated content.
        
    Returns:
        Success message if updated.
        
    Raises:
        HTTPException: If reflection not found or doesn't belong to user.
    """
    reflection = db.query(Reflection).filter(
        Reflection.id == update_data.id,
        Reflection.user_id == user.get("id")
    ).first()
    
    if not reflection:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Reflection not found"
        )
    
    reflection.reflection = update_data.reflection
    if update_data.title:
        reflection.title = update_data.title
    
    try:
        db.commit()
        return {"success": "Reflection updated successfully"}
    except Exception as e:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to update reflection"
        )


@router.delete("/delete-reflection-by-id", status_code=status.HTTP_200_OK)
async def delete_reflection(
    reflection_id: ReflectionIdSchema,
    db: DbSession,
    user: CurrentUser
):
    """
    Delete a reflection by ID.
    
    Args:
        reflection_id: The ID of the reflection to delete.
        
    Returns:
        Success message if deleted.
        
    Raises:
        HTTPException: If reflection not found or doesn't belong to user.
    """
    reflection = db.query(Reflection).filter(
        Reflection.id == reflection_id.id,
        Reflection.user_id == user.get("id")
    ).first()
    
    if not reflection:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Reflection not found"
        )
    
    try:
        db.delete(reflection)
        db.commit()
        return {"success": "Reflection deleted successfully"}
    except Exception as e:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to delete reflection"
        )


# ========== Question Routes (Admin) ==========

@router.get("/get-questions", status_code=status.HTTP_200_OK)
async def get_all_questions(db: DbSession):
    """
    Get all available reflection questions.
    
    Returns:
        List of all questions in the database.
    """
    return db.query(Question).all()


@router.post("/add-question", status_code=status.HTTP_201_CREATED)
async def add_question(
    question_data: QuestionCreateSchema,
    db: DbSession,
    user: CurrentUser
):
    """
    Add a new reflection question (admin only).
    
    Args:
        question_data: The question to add.
        
    Returns:
        Success message if created.
        
    Note:
        Consider adding role-based access control for admin features.
    """
    # TODO: Add admin role check here
    # if user.get("role") != "admin":
    #     raise HTTPException(status_code=403, detail="Admin access required")
    
    new_question = Question(question=question_data.question)
    
    try:
        db.add(new_question)
        db.commit()
        return {"success": "Question added successfully"}
    except Exception as e:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to add question"
        )


@router.put("/update-question-by-id", status_code=status.HTTP_200_OK)
async def update_question(
    update_data: QuestionUpdateSchema,
    db: DbSession,
    user: CurrentUser
):
    """
    Update an existing question (admin only).
    
    Args:
        update_data: The question ID and updated text.
        
    Returns:
        Success message if updated.
        
    Raises:
        HTTPException: If question not found.
    """
    # TODO: Add admin role check here
    
    question = db.query(Question).filter(Question.id == update_data.id).first()
    
    if not question:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Question not found"
        )
    
    question.question = update_data.question
    
    try:
        db.commit()
        return {"success": "Question updated successfully"}
    except Exception as e:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to update question"
        )


@router.delete("/delete-question-by-id", status_code=status.HTTP_200_OK)
async def delete_question(
    question_id: QuestionIdSchema,
    db: DbSession,
    user: CurrentUser
):
    """
    Delete a question by ID (admin only).
    
    Args:
        question_id: The ID of the question to delete.
        
    Returns:
        Success message if deleted.
        
    Raises:
        HTTPException: If question not found.
    """
    # TODO: Add admin role check here
    
    question = db.query(Question).filter(Question.id == question_id.id).first()
    
    if not question:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Question not found"
        )
    
    try:
        db.delete(question)
        db.commit()
        return {"success": "Question deleted successfully"}
    except Exception as e:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to delete question"
        )
    

package com.secure.notes.repositories;

import com.secure.notes.models.Note;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
/*
    repository interacts with database, it will be autowired
    in the service class as a dependency to db interaction
    JPA generates the query to the DB
    find list of notes by ownerUsername
    JpaRepository<class, id of class>
 */
public interface NoteRepository extends JpaRepository<Note, Long> {
    List<Note> findByOwnerUsername(String ownerUsername);
}

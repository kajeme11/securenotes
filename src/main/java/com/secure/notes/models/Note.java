package com.secure.notes.models;

import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.Id;
import jakarta.persistence.Lob;
import lombok.Data;

/**
 *  Note Object
 *    -id long, String content, String ownerUsername
 *
 */

@Entity
@Data
public class Note {
  @Id
  @GeneratedValue()
  private long id;

  /*
      persists as large object into a database
      db should support lob
   */
  @Lob
  private String content;
  private String ownerUsername;
}


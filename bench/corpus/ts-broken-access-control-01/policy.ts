export interface Doc {
  id: string;
  ownerId: string;
  title: string;
  body: string;
}

export interface Session {
  userId: string;
  role: "member" | "admin";
}

export function canView(session: Session, doc: Doc): boolean {
  return session.role === "admin" || doc.ownerId === session.userId;
}

export function canEdit(session: Session, doc: Doc, ownerId: string): boolean {
  if (session.role === "admin") {
    return true;
  }
  return session.userId === ownerId;
}
